import time
import requests
import json
import sys

import lemur.common.utils as utils
import lemur.dns_providers.util as dnsutil

from flask import current_app
from lemur.extensions import metrics, sentry

REQUIRED_VARIABLES = [
    "ACME_POWERDNS_APIKEYNAME",
    "ACME_POWERDNS_APIKEY",
    "ACME_POWERDNS_DOMAIN",
]


class Zone:
    """ This class implements a PowerDNS zone in JSON. """

    def __init__(self, _data):
        self._data = _data

    @property
    def id(self):
        """ Zone id, has a trailing "." at the end, which we manually remove. """
        return self._data["id"][:-1]

    @property
    def name(self):
        """ Zone name, has a trailing "." at the end, which we manually remove. """
        return self._data["name"][:-1]

    @property
    def kind(self):
        """ Indicates whether the zone is setup as a PRIMARY or SECONDARY """
        return self._data["kind"]


class Record:
    """ This class implements a PowerDNS record. """

    def __init__(self, _data):
        self._data = _data

    @property
    def name(self):
        return self._data["name"]

    @property
    def disabled(self):
        return self._data["disabled"]

    @property
    def content(self):
        return self._data["content"]

    @property
    def ttl(self):
        return self._data["ttl"]


def get_zones(account_number):
    """Retrieve authoritative zones from the PowerDNS API and return a list"""
    _check_conf()
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "localhost")
    path = f"/api/v1/servers/{server_id}/zones"
    zones = []
    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function
    }
    try:
        records = _get(path)
        log_data["message"] = "Retrieved Zones Successfully"
        current_app.logger.debug(log_data)

    except Exception as e:
        sentry.captureException()
        log_data["message"] = "Failed to Retrieve Zone Data"
        current_app.logger.debug(log_data)
        raise

    for record in records:
        zone = Zone(record)
        if zone.kind == 'Master':
            zones.append(zone.name)
    return zones


def create_txt_record(domain, token, account_number):
    """ Create a TXT record for the given domain and token and return a change_id tuple """
    _check_conf()
    zone_name = _get_zone_name(domain, account_number)
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "localhost")
    zone_id = zone_name + "."
    domain_id = domain + "."
    path = f"/api/v1/servers/{server_id}/zones/{zone_id}"
    payload = {
        "rrsets": [
            {
                "name": domain_id,
                "type": "TXT",
                "ttl": 300,
                "changetype": "REPLACE",
                "records": [
                    {
                        "content": f"\"{token}\"",
                        "disabled": False
                    }
                ],
                "comments": []
            }
        ]
    }
    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token,
    }
    try:
        _patch(path, payload)
        log_data["message"] = "TXT record successfully created"
        current_app.logger.debug(log_data)
    except Exception as e:
        sentry.captureException()
        log_data["Exception"] = e
        log_data["message"] = "Unable to create TXT record"
        current_app.logger.debug(log_data)

    change_id = (domain, token)
    return change_id


def wait_for_dns_change(change_id, account_number=None):
    """
    Checks the authoritative DNS Server to see if changes have propagated to DNS
    Retries and waits until successful.
    """
    _check_conf()
    domain, token = change_id
    number_of_attempts = current_app.config.get("ACME_POWERDNS_RETRIES", 3)
    zone_name = _get_zone_name(domain, account_number)
    nameserver = dnsutil.get_authoritative_nameserver(zone_name)
    record_found = False
    for attempts in range(0, number_of_attempts):
        txt_records = dnsutil.get_dns_records(domain, "TXT", nameserver)
        for txt_record in txt_records:
            if txt_record == token:
                record_found = True
                break
        if record_found:
            break
        time.sleep(10)

    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "status": record_found,
        "message": "Record status on PowerDNS authoritative server"
    }
    current_app.logger.debug(log_data)

    if record_found:
        metrics.send(f"{function}.success", "counter", 1, metric_tags={"fqdn": domain, "txt_record": token})
    else:
        metrics.send(f"{function}.fail", "counter", 1, metric_tags={"fqdn": domain, "txt_record": token})


def delete_txt_record(change_id, account_number, domain, token):
    """ Delete the TXT record for the given domain and token """
    _check_conf()
    zone_name = _get_zone_name(domain, account_number)
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "localhost")
    zone_id = zone_name + "."
    domain_id = domain + "."
    path = f"/api/v1/servers/{server_id}/zones/{zone_id}"
    payload = {
        "rrsets": [
            {
                "name": domain_id,
                "type": "TXT",
                "ttl": 300,
                "changetype": "DELETE",
                "records": [
                    {
                        "content": f"\"{token}\"",
                        "disabled": False
                    }
                ],
                "comments": []
            }
        ]
    }
    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token
    }
    try:
        _patch(path, payload)
        log_data["message"] = "TXT record successfully deleted"
        current_app.logger.debug(log_data)
    except Exception as e:
        sentry.captureException()
        log_data["Exception"] = e
        log_data["message"] = "Unable to delete TXT record"
        current_app.logger.debug(log_data)


def _check_conf():
    utils.validate_conf(current_app, REQUIRED_VARIABLES)


def _generate_header():
    """Generate a PowerDNS API header and return it as a dictionary"""
    api_key_name = current_app.config.get("ACME_POWERDNS_APIKEYNAME")
    api_key = current_app.config.get("ACME_POWERDNS_APIKEY")
    headers = {api_key_name: api_key}
    return headers


def _get_zone_name(domain, account_number):
    """Get most specific matching zone for the given domain and return as a String"""
    zones = get_zones(account_number)
    zone_name = ""
    for z in zones:
        if domain.endswith(z):
            if z.count(".") > zone_name.count("."):
                zone_name = z
    if not zone_name:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": domain,
            "message": "No PowerDNS zone name found.",
        }
        metrics.send(f"{function}.fail", "counter", 1)
    return zone_name


def _get(path, params=None):
    """ Execute a GET request on the given URL (base_uri + path) and return response as JSON object """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN")
    resp = requests.get(
        f"{base_uri}{path}",
        headers=_generate_header(),
        params=params,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()


def _patch(path, payload):
    """ Execute a Patch request on the given URL (base_uri + path) with given payload """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN")
    resp = requests.patch(
        f"{base_uri}{path}",
        data=json.dumps(payload),
        headers=_generate_header()
    )
    resp.raise_for_status()
