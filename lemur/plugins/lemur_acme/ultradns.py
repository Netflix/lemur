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
from sentry_sdk import capture_exception

from lemur.extensions import metrics


class Record:
    """
    This class implements an Ultra DNS record.

    Accepts the response from the API call as the argument.
    """

    def __init__(self, _data):
        # Since we are dealing with only TXT records for Lemur, we expect only 1 RRSet in the response.
        # Thus we default to picking up the first entry (_data["rrsets"][0]) from the response.
        self._data = _data["rrSets"][0]

    @property
    def name(self):
        return self._data["ownerName"]

    @property
    def rrtype(self):
        return self._data["rrtype"]

    @property
    def rdata(self):
        return self._data["rdata"]

    @property
    def ttl(self):
        return self._data["ttl"]


class Zone:
    """
    This class implements an Ultra DNS zone.
    """

    def __init__(self, _data, _client="Client"):
        self._data = _data
        self._client = _client

    @property
    def name(self):
        """
        Zone name, has a trailing "." at the end, which we manually remove.
        """
        return self._data["properties"]["name"][:-1]

    @property
    def authoritative_type(self):
        """
        Indicates whether the zone is setup as a PRIMARY or SECONDARY
        """
        return self._data["properties"]["type"]

    @property
    def record_count(self):
        return self._data["properties"]["resourceRecordCount"]

    @property
    def status(self):
        """
        Returns the status of the zone - ACTIVE, SUSPENDED, etc
        """
        return self._data["properties"]["status"]


def get_ultradns_token():
    """
    Function to call the UltraDNS Authorization API.

    Returns the Authorization access_token which is valid for 1 hour.
    Each request calls this function and we generate a new token every time.
    """
    path = "/v2/authorization/token"
    data = {
        "grant_type": "password",
        "username": current_app.config.get("ACME_ULTRADNS_USERNAME", ""),
        "password": current_app.config.get("ACME_ULTRADNS_PASSWORD", ""),
    }
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.post(f"{base_uri}{path}", data=data, verify=True)
    return resp.json()["access_token"]


def _generate_header():
    """
    Function to generate the header for a request.

    Contains the Authorization access_key obtained from the get_ultradns_token() function.
    """
    access_token = get_ultradns_token()
    return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}


def _paginate(path, key):
    limit = 100
    params = {"offset": 0, "limit": 1}
    resp = _get(path, params)
    for index in range(0, resp["resultInfo"]["totalCount"], limit):
        params["offset"] = index
        params["limit"] = limit
        resp = _get(path, params)
        yield resp[key]


def _get(path, params=None):
    """Function to execute a GET request on the given URL (base_uri + path) with given params"""
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.get(
        f"{base_uri}{path}",
        headers=_generate_header(),
        params=params,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()


def _delete(path):
    """Function to execute a DELETE request on the given URL"""
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.delete(
        f"{base_uri}{path}",
        headers=_generate_header(),
        verify=True,
    )
    resp.raise_for_status()


def _post(path, params):
    """Executes a POST request on given URL. Body is sent in JSON format"""
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.post(
        f"{base_uri}{path}",
        headers=_generate_header(),
        data=json.dumps(params),
        verify=True,
    )
    resp.raise_for_status()


def _has_dns_propagated(name, token, domain):
    """
    Check whether the DNS change made by Lemur have propagated to the public DNS or not.

    Invoked by wait_for_dns_change() function
    """
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


def wait_for_dns_change(change_id, account_number=None):
    """
    Waits and checks if the DNS changes have propagated or not.

    First check the domains authoritative server. Once this succeeds,
    we ask a public DNS server (Google <8.8.8.8> in our case).
    """
    fqdn, token = change_id
    number_of_attempts = 20
    nameserver = get_authoritative_nameserver(fqdn)
    for attempts in range(0, number_of_attempts):
        status = _has_dns_propagated(fqdn, token, nameserver)
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": fqdn,
            "status": status,
            "message": "Record status on ultraDNS authoritative server"
        }
        current_app.logger.debug(log_data)
        if status:
            time.sleep(10)
            break
        time.sleep(10)
    if status:
        nameserver = get_public_authoritative_nameserver()
        for attempts in range(0, number_of_attempts):
            status = _has_dns_propagated(fqdn, token, nameserver)
            log_data = {
                "function": function,
                "fqdn": fqdn,
                "status": status,
                "message": "Record status on Public DNS"
            }
            current_app.logger.debug(log_data)
            if status:
                metrics.send(f"{function}.success", "counter", 1)
                break
            time.sleep(10)
    if not status:
        metrics.send(f"{function}.fail", "counter", 1, metric_tags={"fqdn": fqdn, "txt_record": token})
        capture_exception(extra={"fqdn": str(fqdn), "txt_record": str(token)})
    return


def get_zones(account_number):
    """Get zones from the UltraDNS"""
    path = "/v2/zones"
    zones = []
    for page in _paginate(path, "zones"):
        for elem in page:
            # UltraDNS zone names end with a "." - Example - lemur.example.com.
            # We pick out the names minus the "." at the end while returning the list
            zone = Zone(elem)
            if zone.authoritative_type == "PRIMARY" and zone.status == "ACTIVE":
                zones.append(zone.name)

    return zones


def get_zone_name(domain, account_number):
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
        raise Exception(f"No UltraDNS zone found for domain: {domain}")
    return zone_name


def create_txt_record(domain, token, account_number):
    """
    Create a TXT record for the given domain.

    The part of the domain that matches with the zone becomes the zone name.
    The remainder becomes the owner name (referred to as node name here)
    Example: Let's say we have a zone named "exmaple.com" in UltraDNS and we
    get a request to create a cert for lemur.example.com
    Domain - _acme-challenge.lemur.example.com
    Matching zone - example.com
    Owner name - _acme-challenge.lemur
    """

    zone_name = get_zone_name(domain, account_number)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = f"{node_name}.{zone_name}"
    path = f"/v2/zones/{zone_name}/rrsets/TXT/{node_name}"
    params = {
        "ttl": 5,
        "rdata": [
            f"{token}"
        ],
    }

    try:
        _post(path, params)
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "fqdn": fqdn,
            "token": token,
            "message": "TXT record created"
        }
        current_app.logger.debug(log_data)
    except Exception as e:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "domain": domain,
            "token": token,
            "Exception": e,
            "message": "Unable to add record. Record already exists."
        }
        current_app.logger.debug(log_data)

    change_id = (fqdn, token)
    return change_id


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

    if not domain:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "message": "No domain passed"
        }
        current_app.logger.debug(log_data)
        return

    zone_name = get_zone_name(domain, account_number)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    path = f"/v2/zones/{zone_name}/rrsets/16/{node_name}"

    try:
        rrsets = _get(path)
        record = Record(rrsets)
    except Exception as e:
        function = sys._getframe().f_code.co_name
        metrics.send(f"{function}.geterror", "counter", 1)
        # No Text Records remain or host is not in the zone anymore because all records have been deleted.
        return
    try:
        # Remove the record from the RRSet locally
        record.rdata.remove(f"{token}")
    except ValueError:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "token": token,
            "message": "Token not found"
        }
        current_app.logger.debug(log_data)
        return

    # Delete the RRSet from UltraDNS
    _delete(path)

    # Check if the RRSet has more records. If yes, add the modified RRSet back to UltraDNS
    if len(record.rdata) > 0:
        params = {
            "ttl": 5,
            "rdata": record.rdata,
        }
        _post(path, params)


def delete_acme_txt_records(domain):

    if not domain:
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "message": "No domain passed"
        }
        current_app.logger.debug(log_data)
        return
    acme_challenge_string = "_acme-challenge"
    if not domain.startswith(acme_challenge_string):
        function = sys._getframe().f_code.co_name
        log_data = {
            "function": function,
            "domain": domain,
            "acme_challenge_string": acme_challenge_string,
            "message": "Domain does not start with the acme challenge string"
        }
        current_app.logger.debug(log_data)
        return

    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    path = f"/v2/zones/{zone_name}/rrsets/16/{node_name}"

    _delete(path)


def get_authoritative_nameserver(domain):
    """Get the authoritative nameserver for the given domain"""
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == "@"
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


def get_public_authoritative_nameserver():
    return "8.8.8.8"
