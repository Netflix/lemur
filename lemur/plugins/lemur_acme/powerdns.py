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
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "")
    path = f"/api/v1/servers/{server_id}/zones"
    zones = []
    for elem in _get(path):
        zone = Zone(elem)
        if zone.kind == 'Master':
            zones.append(zone.name)
    return zones


def create_txt_record(domain, token, account_number):
    """ Create a TXT record for the given domain and token and return a change_id tuple """
    zone_name = _get_zone_name(domain, account_number)
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "")
    zone_id = zone_name + "."
    domain_id = domain + "."
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
    except requests.exceptions.RequestException as e:
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
    Checks if changes have propagated to DNS
    Verifies both the authoritative DNS server and a public DNS server(Google <8.8.8.8> in our case)
    Retries and waits until successful.
    """
    domain, token = change_id
    number_of_attempts = 20

    nameserver = _get_authoritative_nameserver(domain)
    status = False
    for attempts in range(0, number_of_attempts):
        status = _has_dns_propagated(domain, token, nameserver)
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": domain,
            "status": status,
            "message": "Record status on UltraDNS authoritative server"
        }
        current_app.logger.debug(log_data)
        if status:
            time.sleep(10)
            break
        time.sleep(10)
    if status:
        nameserver = _get_public_authoritative_nameserver()
        for attempts in range(0, number_of_attempts):
            status = _has_dns_propagated(domain, token, nameserver)
            function = sys._getframe().f_code.co_name
            log_data = {
                "function": function,
                "fqdn": domain,
                "status": status,
                "message": "Record status on Public DNS"
            }
            current_app.logger.debug(log_data)
            if status:
                metrics.send(f"{function}.success", "counter", 1)
                break
            time.sleep(10)
    if not status:
        metrics.send(f"{function}.fail", "counter", 1, metric_tags={"fqdn": domain, "txt_record": token})
        sentry.captureException(extra={"fqdn": str(domain), "txt_record": str(token)})


def delete_txt_record(change_id, account_number, domain, token):
    """ Delete the TXT record for the given domain and token """
    zone_name = _get_zone_name(domain, account_number)
    server_id = current_app.config.get("ACME_POWERDNS_SERVERID", "")
    zone_id = zone_name + "."
    domain_id = domain + "."
    path = f"/api/v1/servers/{server_id}/zones/{zone_id}"
    payload = {
        "rrsets": [
            {
                "name": f"{domain_id}",
                "type": "TXT",
                "ttl": "300",
                "changetype": "DELETE",
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
            "message": "TXT record successfully deleted"
        }
        current_app.logger.debug(log_data)
    except requests.exceptions.RequestException as e:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "domain": domain,
            "token": token,
            "Exception": e,
            "message": "Unable to delete TXT record"
        }
        current_app.logger.debug(log_data)


def _generate_header():
    """Generate a PowerDNS API header and return it as a dictionary"""
    api_key_name = current_app.config.get("ACME_POWERDNS_APIKEYNAME", "")
    api_key = current_app.config.get("ACME_POWERDNS_APIKEY", "")
    return {api_key_name: api_key}


def _get(path, params=None):
    """ Execute a GET request on the given URL (base_uri + path) and return response as JSON object """
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
    """ Execute a Patch request on the given URL (base_uri + path) with given payload """
    base_uri = current_app.config.get("ACME_POWERDNS_DOMAIN", "")
    resp = requests.patch(
        f"{base_uri}{path}",
        headers=_generate_header(),
        data=json.dumps(payload)
    )
    resp.raise_for_status()


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
        metrics.send(f"{function}.fail", "counter", 1)
        raise Exception(f"No PowerDNS zone found for domain: {domain}")
    return zone_name


def _get_authoritative_nameserver(domain):
    """Get the authoritative nameserver for the given domain"""
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u"@"
        sub = s[1]

        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            function = sys._getframe().f_code.co_name
            metrics.send(f"{function}.error", "counter", 1)
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception("%s does not exist." % sub)
            else:
                raise Exception("Error %s" % dns.rcode.to_text(rcode))

        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype != dns.rdatatype.SOA:
            authority = rr.target
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1

    return nameserver


def _get_public_authoritative_nameserver():
    return "8.8.8.8"


def _has_dns_propagated(name, token, domain):
    """Check whether the DNS change has propagated to the public DNS"""
    txt_records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [domain]
        dns_response = dns_resolver.query(name, "TXT")
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record.decode("utf-8"))
    except dns.exception.DNSException:
        function = sys._getframe().f_code.co_name
        metrics.send(f"{function}.fail", "counter", 1)
        return False

    for txt_record in txt_records:
        if txt_record == token:
            function = sys._getframe().f_code.co_name
            metrics.send(f"{function}.success", "counter", 1)
            return True

    return False
