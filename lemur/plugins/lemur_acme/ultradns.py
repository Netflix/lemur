import time
import requests
import json

import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver

from flask import current_app
from lemur.extensions import metrics, sentry

use_http = False


def get_ultradns_token():
    path = "/v2/authorization/token"
    data = {
        "grant_type": "password",
        "username": current_app.config.get("ACME_ULTRADNS_USERNAME", ""),
        "password": current_app.config.get("ACME_ULTRADNS_PASSWORD", ""),
    }
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.post("{0}{1}".format(base_uri, path), data=data, verify=True)
    return resp.json()["access_token"]


def _generate_header():
    access_token = get_ultradns_token()
    return {"Authorization": "Bearer {}".format(access_token), "Content-Type": "application/json"}


def _paginate(path, key):
    limit = 100
    params = {"offset": 0, "limit": 1}
    # params["offset"] = 0
    # params["limit"] = 1
    resp = _get(path, params)
    for index in range(0, resp["resultInfo"]["totalCount"], limit):
        params["offset"] = index
        params["limit"] = limit
        resp = _get(path, params)
        yield resp[key]


def _get(path, params=None):
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.get(
        "{0}{1}".format(base_uri, path),
        headers=_generate_header(),
        params=params,
        verify=True,
    )
    resp.raise_for_status()
    return resp.json()


def _delete(path):
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.delete(
        "{0}{1}".format(base_uri, path),
        headers=_generate_header(),
        verify=True,
    )
    resp.raise_for_status()


def _post(path, params):
    base_uri = current_app.config.get("ACME_ULTRADNS_DOMAIN", "")
    resp = requests.post(
        "{0}{1}".format(base_uri, path),
        headers=_generate_header(),
        data=json.dumps(params),
        verify=True,
    )
    resp.raise_for_status()


def _has_dns_propagated(name, token):
    txt_records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [get_authoritative_nameserver(name)]
        dns_response = dns_resolver.query(name, "TXT")
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record.decode("utf-8"))
    except dns.exception.DNSException:
        metrics.send("has_dns_propagated_fail", "counter", 1)
        return False

    for txt_record in txt_records:
        if txt_record == token:
            metrics.send("has_dns_propagated_success", "counter", 1)
            return True

    return False


def wait_for_dns_change(change_id, account_number=None):
    fqdn, token = change_id
    number_of_attempts = 20
    for attempts in range(0, number_of_attempts):
        status = _has_dns_propagated(fqdn, token)
        current_app.logger.debug("Record status for fqdn: {}: {}".format(fqdn, status))
        if status:
            metrics.send("wait_for_dns_change_success", "counter", 1)
            break
        time.sleep(10)
    if not status:
        # TODO: Delete associated DNS text record here
        metrics.send("wait_for_dns_change_fail", "counter", 1)
        sentry.captureException(extra={"fqdn": str(fqdn), "txt_record": str(token)})
        metrics.send(
            "wait_for_dns_change_error",
            "counter",
            1,
            metric_tags={"fqdn": fqdn, "txt_record": token},
        )
    return


def get_zones(account_number):
    path = "/v2/zones/"
    zones = []
    for page in _paginate(path, "zones"):
        for elem in page:
            zones.append(elem["properties"]["name"][:-1])

    return zones


def get_zone_name(domain, account_number):
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
        metrics.send("ultradns_no_zone_name", "counter", 1)
        raise Exception("No UltraDNS zone found for domain: {}".format(domain))
    return zone_name


def create_txt_record(domain, token, account_number):
    zone_name = get_zone_name(domain, account_number)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)
    path = "/v2/zones/{0}/rrsets/TXT/{1}".format(zone_name, node_name)
    # zone = Zone(zone_name)
    params = {
        "ttl": 300,
        "rdata": [
            "{}".format(token)
        ],
    }

    try:
        _post(path, params)
        current_app.logger.debug(
            "TXT record created: {0}, token: {1}".format(fqdn, token)
        )
    except Exception as e:
        current_app.logger.debug(
            "Unable to add record. Domain: {}. Token: {}. "
            "Record already exists: {}".format(domain, token, e),
            exc_info=True,
        )

    change_id = (fqdn, token)
    return change_id


def delete_txt_record(change_id, account_number, domain, token):
    # client = get_ultradns_client()
    if not domain:
        current_app.logger.debug("delete_txt_record: No domain passed")
        return

    zone_name = get_zone_name(domain, account_number)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)
    path = "/v2/zones/{}/rrsets/16/{}".format(zone_name, node_name)

    try:
        # rrsets = client.get_rrsets_by_type_owner(zone_name, "TXT", node_name)
        rrsets = _get(path)
    except Exception as e:
        metrics.send("delete_txt_record_geterror", "counter", 1)
        # No Text Records remain or host is not in the zone anymore because all records have been deleted.
        return
    try:
        rrsets["rrSets"][0]["rdata"].remove("{}".format(token))
    except ValueError:
        current_app.logger.debug("Token not found")
        return

    #client.delete_rrset(zone_name, "TXT", node_name)
    _delete(path)

    if len(rrsets["rrSets"][0]["rdata"]) > 0:
        #client.create_rrset(zone_name, "TXT", node_name, 300, rrsets["rrSets"][0]["rdata"])
        params = {
            "ttl": 300,
            "rdata": rrsets["rrSets"][0]["rdata"],
        }
        _post(path, params)


def get_authoritative_nameserver(domain):
    # return "8.8.8.8"
    return "156.154.64.154"
