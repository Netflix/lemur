import time
import requests
import json
import sys

import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver

from flask import current_app
from lemur.extensions import metrics, sentry

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


def _generate_header():
    """Function to generate the header for a request using the PowerDNS API Key"""

    api_key_name = current_app.config.get("ACME_POWERDNS_APIKEYNAME", "")
    api_key = current_app.config.get("ACME_POWERDNS_APIKEY", "")
    return {api_key_name: api_key}


def _get(path, params=None):
    """
    Function to execute a GET request on the given URL (base_uri + path) with given params
    Returns JSON response object
    """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN", "")
    resp = requests.get(
        f"{base_uri}{path}",
        headers=_generate_header(),
        params=params,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()

def _patch(path, payload):
    """
    Function to execute a Patch request on the given URL (base_uri + path) with given data
    """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN", "")
    resp = requests.patch(
        f"{base_uri}{path}",
        headers=_generate_header(),
        data=json.dumps(payload)
    )
    resp.raise_for_status()


def get_zones(account_number):
    """Get zones from the PowerDNS"""
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "")
    path = f"/api/v1/servers/{server_id}/zones"
    zones = []
    for elem in _get(path):
        zone = Zone(elem)
        if zone.kind == 'Master':
            zones.append(zone.name)
    return zones

def _get_zone_name(domain, account_number):
    """Get the matching zone for the given domain"""
    zones = get_zones(account_number)
    zone_name = ""
    for z in zones:
        if domain.endswith(z):
            # Find the most specific zone possible for the domain
            # Ex: If fqdn is a.b.c.com, there is a zone for c.com,
            # and a zone for b.c.com, we want to use b.c.com.
            if z.count(".") > zone_name.count("."):
                zone_name = z
    if not zone_name:
        function = sys._getframe().f_code.co_name
        metrics.send(f"{function}.fail", "counter", 1)
        raise Exception(f"No PowerDNS zone found for domain: {domain}")
    return zone_name

def create_txt_record(domain, token, account_number):
    """
    Create a TXT record for the given domain.

    The part of the domain that matches with the zone becomes the zone name.
    The remainder becomes the owner name (referred to as node name here)
    Example: Let's say we have a zone named "exmaple.com" in PowerDNS and we
    get a request to create a cert for lemur.example.com
    Domain - _acme-challenge.lemur.example.com
    Matching zone - example.com
    Owner name - _acme-challenge.lemur
    """

    zone_name = _get_zone_name(domain, account_number)
    node_name = domain[:-len(".".join(zone_name))]

    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "")
    zone_id = zone_name.join(".")
    domain_id = domain.join(".")

    path = f"/api/v1/servers/{server_id}/zones/{zone_id}"
    payload = {
        "rrsets": [
            {
                "name": f"{domain_id}",
                "type": "TXT",
                "ttl": "300",
                "changetype": "REPLACE",
                "records": [
                    {
                        "content": f"{token}",
                        "disabled": "false"
                    }
                ],
                "comments": []
            }
        ]
    }

    try:
        _patch(path, payload)
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": domain,
            "token": token,
            "message": "TXT record successfully created"
        }
        current_app.logger.debug(log_data)
    except Exception as e:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "domain": domain,
            "token": token,
            "Exception": e,
            "message": "Unable to create TXT record"
        }
        current_app.logger.debug(log_data)

    change_id = (domain, token)
    return change_id


def wait_for_dns_change(change_id, account_number=None):
    """
    Waits and checks if the DNS changes have propagated or not.

    First check the domains authoritative server. Once this succeeds,
    we ask a public DNS server (Google <8.8.8.8> in our case).
    """
    pass

def delete_txt_record(change_id, account_number, domain, token):
    """
    Delete the TXT record that was created in the create_txt_record() function.

    UltraDNS handles records differently compared to Dyn. It creates an RRSet
    which is a set of records of the same type and owner. This means
    that while deleting the record, we cannot delete any individual record from
    the RRSet. Instead, we have to delete the entire RRSet. If multiple certs are
    being created for the same domain at the same time, the challenge TXT records
    that are created will be added under the same RRSet. If the RRSet had more
    than 1 record, then we create a new RRSet on UltraDNS minus the record that
    has to be deleted.
    """
    pass
