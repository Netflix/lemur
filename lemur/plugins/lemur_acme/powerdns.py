import json
import sys
import time

import lemur.common.utils as utils
import lemur.dns_providers.util as dnsutil
import requests
from flask import current_app
from sentry_sdk import capture_exception

from lemur.extensions import metrics

REQUIRED_VARIABLES = [
    "ACME_POWERDNS_APIKEYNAME",
    "ACME_POWERDNS_APIKEY",
    "ACME_POWERDNS_DOMAIN",
]


class Zone:
    """
    This class implements a PowerDNS zone in JSON.
    """

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
    """
    This class implements a PowerDNS record.
    """

    def __init__(self, _data):
        self._data = _data

    @property
    def name(self):
        return self._data["name"]

    @property
    def type(self):
        return self._data["type"]

    @property
    def ttl(self):
        return self._data["ttl"]

    @property
    def content(self):
        return self._data["content"]

    @property
    def disabled(self):
        return self._data["disabled"]


def get_zones(account_number):
    """
    Retrieve authoritative zones from the PowerDNS API and return a list of zones

    :param account_number:
    :raise: Exception
    :return: list of Zone Objects
    """
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
        capture_exception()
        log_data["message"] = "Failed to Retrieve Zone Data"
        current_app.logger.debug(log_data)
        raise

    for record in records:
        zone = Zone(record)
        if zone.kind == 'Master':
            zones.append(zone.name)
    return zones


def create_txt_record(domain, token, account_number):
    """
    Create a TXT record for the given domain and token and return a change_id tuple

    :param domain: FQDN
    :param token: challenge value
    :param account_number:
    :return: tuple of domain/token
    """
    _check_conf()

    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token,
    }

    # Create new record
    domain_id = domain + "."
    records = [Record({'name': domain_id, 'content': f"\"{token}\"", 'disabled': False})]

    # Get current records
    cur_records = _get_txt_records(domain)
    for record in cur_records:
        if record.content != token:
            records.append(record)

    try:
        _patch_txt_records(domain, account_number, records)
        log_data["message"] = "TXT record(s) successfully created"
        current_app.logger.debug(log_data)
    except Exception as e:
        capture_exception()
        log_data["Exception"] = e
        log_data["message"] = "Unable to create TXT record(s)"
        current_app.logger.debug(log_data)

    change_id = (domain, token)
    return change_id


def wait_for_dns_change(change_id, account_number=None):
    """
    Checks the authoritative DNS Server to see if changes have propagated.

    :param change_id: tuple of domain/token
    :param account_number:
    :return:
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
    """
    Delete the TXT record for the given domain and token

    :param change_id: tuple of domain/token
    :param account_number:
    :param domain: FQDN
    :param token: challenge to delete
    :return:
    """
    _check_conf()

    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function,
        "fqdn": domain,
        "token": token,
    }

    """
    Get existing TXT records matching the domain from DNS
    The token to be deleted should already exist
    There may be other records with different tokens as well
    """
    cur_records = _get_txt_records(domain)
    found = False
    new_records = []
    for record in cur_records:
        if record.content == f"\"{token}\"":
            found = True
        else:
            new_records.append(record)

    # Since the matching token is not in DNS, there is nothing to delete
    if not found:
        log_data["message"] = "Unable to delete TXT record: Token not found in existing TXT records"
        current_app.logger.debug(log_data)
        return

    # The record to delete has been found AND there are other tokens set on the same domain
    # Since we only want to delete one token value from the RRSet, we need to use the Patch command to
    # overwrite the current RRSet with the existing records.
    elif new_records:
        try:
            _patch_txt_records(domain, account_number, new_records)
            log_data["message"] = "TXT record successfully deleted"
            current_app.logger.debug(log_data)
        except Exception as e:
            capture_exception()
            log_data["Exception"] = e
            log_data["message"] = "Unable to delete TXT record: patching exception"
            current_app.logger.debug(log_data)

    # The record to delete has been found AND there are no other token values set on the same domain
    # Use the Delete command to delete the whole RRSet.
    else:
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
            capture_exception()
            log_data["Exception"] = e
            log_data["message"] = "Unable to delete TXT record"
            current_app.logger.debug(log_data)


def _check_conf():
    """
    Verifies required configuration variables are set

    :return:
    """
    utils.validate_conf(current_app, REQUIRED_VARIABLES)


def _generate_header():
    """
    Generate a PowerDNS API header and return it as a dictionary

    :return: Dict of header parameters
    """
    api_key_name = current_app.config.get("ACME_POWERDNS_APIKEYNAME")
    api_key = current_app.config.get("ACME_POWERDNS_APIKEY")
    headers = {api_key_name: api_key}
    return headers


def _get_zone_name(domain, account_number):
    """
    Get most specific matching zone for the given domain and return as a String

    :param domain: FQDN
    :param account_number:
    :return: FQDN of domain
    """
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


def _get_txt_records(domain):
    """
    Retrieve TXT records for a given domain and return list of Record Objects

    :param domain: FQDN
    :return: list of Record objects
    """
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "localhost")

    path = f"/api/v1/servers/{server_id}/search-data?q={domain}&max=100&object_type=record"
    function = sys._getframe().f_code.co_name
    log_data = {
        "function": function
    }
    try:
        records = _get(path)
        log_data["message"] = "Retrieved TXT Records Successfully"
        current_app.logger.debug(log_data)

    except Exception as e:
        capture_exception()
        log_data["Exception"] = e
        log_data["message"] = "Failed to Retrieve TXT Records"
        current_app.logger.debug(log_data)
        return []

    txt_records = []
    for record in records:
        cur_record = Record(record)
        txt_records.append(cur_record)
    return txt_records


def _get(path, params=None):
    """
    Execute a GET request on the given URL (base_uri + path) and return response as JSON object

    :param path: Relative URL path
    :param params: additional parameters
    :return: json response
    """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN")
    verify_value = current_app.config.get("ACME_POWERDNS_VERIFY", True)
    resp = requests.get(
        f"{base_uri}{path}",
        headers=_generate_header(),
        params=params,
        verify=verify_value
    )
    resp.raise_for_status()
    return resp.json()


def _patch_txt_records(domain, account_number, records):
    """
    Send Patch request to PowerDNS Server

    :param domain: FQDN
    :param account_number:
    :param records: List of Record objects
    :return:
    """
    domain_id = domain + "."

    # Create records
    txt_records = []
    for record in records:
        txt_records.append(
            {'content': record.content, 'disabled': record.disabled}
        )

    # Create RRSet
    payload = {
        "rrsets": [
            {
                "name": domain_id,
                "type": "TXT",
                "ttl": 300,
                "changetype": "REPLACE",
                "records": txt_records,
                "comments": []
            }
        ]
    }

    # Create Txt Records
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "localhost")
    zone_name = _get_zone_name(domain, account_number)
    zone_id = zone_name + "."
    path = f"/api/v1/servers/{server_id}/zones/{zone_id}"
    _patch(path, payload)


def _patch(path, payload):
    """
    Execute a Patch request on the given URL (base_uri + path) with given payload

    :param path:
    :param payload:
    :return:
    """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN")
    verify_value = current_app.config.get("ACME_POWERDNS_VERIFY", True)
    resp = requests.patch(
        f"{base_uri}{path}",
        data=json.dumps(payload),
        headers=_generate_header(),
        verify=verify_value
    )
    resp.raise_for_status()
