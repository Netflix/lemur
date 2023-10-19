import time

import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver
from dyn.tm.errors import (
    DynectCreateError,
    DynectDeleteError,
    DynectGetError,
    DynectUpdateError,
)
from dyn.tm.session import DynectSession
from dyn.tm.zones import Node, Zone, get_all_zones
from flask import current_app
from sentry_sdk import capture_exception

from lemur.extensions import metrics


def get_dynect_session():
    try:
        dynect_session = DynectSession(
            current_app.config.get("ACME_DYN_CUSTOMER_NAME", ""),
            current_app.config.get("ACME_DYN_USERNAME", ""),
            current_app.config.get("ACME_DYN_PASSWORD", ""),
        )
    except Exception as e:
        capture_exception()
        metrics.send("get_dynect_session_fail", "counter", 1)
        current_app.logger.debug("Unable to establish connection to Dyn", exc_info=True)
        raise
    return dynect_session


def _has_dns_propagated(fqdn, token):
    txt_records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [get_authoritative_nameserver(fqdn)]
        dns_response = dns_resolver.query(fqdn, "TXT")
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record.decode("utf-8"))
    except dns.exception.DNSException:
        metrics.send("has_dns_propagated_fail", "counter", 1, metric_tags={"dns": fqdn})
        return False

    for txt_record in txt_records:
        if txt_record == token:
            metrics.send("has_dns_propagated_success", "counter", 1, metric_tags={"dns": fqdn})
            return True

    return False


def wait_for_dns_change(change_id, account_number=None):
    fqdn, token = change_id
    number_of_attempts = 20
    for attempts in range(0, number_of_attempts):
        status = _has_dns_propagated(fqdn, token)
        current_app.logger.debug(f"Record status for fqdn: {fqdn}: {status}")
        if status:
            metrics.send("wait_for_dns_change_success", "counter", 1, metric_tags={"dns": fqdn})
            break
        time.sleep(10)
    if not status:
        # TODO: Delete associated DNS text record here
        metrics.send("wait_for_dns_change_fail", "counter", 1, metric_tags={"dns": fqdn})
        capture_exception(extra={"fqdn": str(fqdn), "txt_record": str(token)})
        metrics.send(
            "wait_for_dns_change_error",
            "counter",
            1,
            metric_tags={"fqdn": fqdn, "txt_record": token},
        )
    return


def get_zone_name(domain):
    zones = get_all_zones()

    zone_name = ""

    for z in zones:
        if domain.endswith(z.name):
            # Find the most specific zone possible for the domain
            # Ex: If fqdn is a.b.c.com, there is a zone for c.com,
            # and a zone for b.c.com, we want to use b.c.com.
            if z.name.count(".") > zone_name.count("."):
                zone_name = z.name
    if not zone_name:
        metrics.send("dyn_no_zone_name", "counter", 1)
        raise Exception(f"No Dyn zone found for domain: {domain}")
    return zone_name


def get_zones(account_number):
    get_dynect_session()
    zones = get_all_zones()
    zone_list = []
    for zone in zones:
        zone_list.append(zone.name)
    return zone_list


def create_txt_record(domain, token, account_number):
    get_dynect_session()
    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = f"{node_name}.{zone_name}"
    zone = Zone(zone_name)

    try:
        zone.add_record(
            node_name, record_type="TXT", txtdata=f'"{token}"', ttl=5
        )
        zone.publish()
        current_app.logger.debug(
            f"TXT record created: {fqdn}, token: {token}"
        )
    except (DynectCreateError, DynectUpdateError) as e:
        if "Cannot duplicate existing record data" in e.message:
            current_app.logger.debug(
                "Unable to add record. Domain: {}. Token: {}. "
                "Record already exists: {}".format(domain, token, e),
                exc_info=True,
            )
        else:
            metrics.send("create_txt_record_error", "counter", 1)
            capture_exception()
            raise

    change_id = (fqdn, token)
    return change_id


def delete_txt_record(change_id, account_number, domain, token):
    get_dynect_session()
    if not domain:
        current_app.logger.debug("delete_txt_record: No domain passed")
        return

    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = f"{node_name}.{zone_name}"

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)

    try:
        all_txt_records = node.get_all_records_by_type("TXT")
    except DynectGetError:
        metrics.send("delete_txt_record_geterror", "counter", 1)
        # No Text Records remain or host is not in the zone anymore because all records have been deleted.
        return
    for txt_record in all_txt_records:
        if txt_record.txtdata == (f"{token}"):
            current_app.logger.debug(f"Deleting TXT record name: {fqdn}")
            try:
                txt_record.delete()
            except DynectDeleteError:
                capture_exception(
                    extra={
                        "fqdn": str(fqdn),
                        "zone_name": str(zone_name),
                        "node_name": str(node_name),
                        "txt_record": str(txt_record.txtdata),
                    }
                )
                metrics.send(
                    "delete_txt_record_deleteerror",
                    "counter",
                    1,
                    metric_tags={"fqdn": fqdn, "txt_record": txt_record.txtdata},
                )

    try:
        zone.publish()
    except DynectUpdateError:
        capture_exception(
            extra={
                "fqdn": str(fqdn),
                "zone_name": str(zone_name),
                "node_name": str(node_name),
                "txt_record": str(txt_record.txtdata),
            }
        )
        metrics.send(
            "delete_txt_record_publish_error",
            "counter",
            1,
            metric_tags={"fqdn": str(fqdn), "txt_record": str(txt_record.txtdata)},
        )


def delete_acme_txt_records(domain):
    get_dynect_session()
    if not domain:
        current_app.logger.debug("delete_acme_txt_records: No domain passed")
        return
    acme_challenge_string = "_acme-challenge"
    if not domain.startswith(acme_challenge_string):
        current_app.logger.debug(
            "delete_acme_txt_records: Domain {} doesn't start with string {}. "
            "Cowardly refusing to delete TXT records".format(
                domain, acme_challenge_string
            )
        )
        return

    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split("."))
    node_name = ".".join(domain.split(".")[:-zone_parts])
    fqdn = f"{node_name}.{zone_name}"

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)

    all_txt_records = node.get_all_records_by_type("TXT")
    for txt_record in all_txt_records:
        current_app.logger.debug(f"Deleting TXT record name: {fqdn}")
        try:
            txt_record.delete()
        except DynectDeleteError:
            capture_exception(
                extra={
                    "fqdn": str(fqdn),
                    "zone_name": str(zone_name),
                    "node_name": str(node_name),
                    "txt_record": str(txt_record.txtdata),
                }
            )
            metrics.send(
                "delete_txt_record_deleteerror",
                "counter",
                1,
                metric_tags={"fqdn": fqdn, "txt_record": txt_record.txtdata},
            )
    zone.publish()


def get_authoritative_nameserver(domain):
    if current_app.config.get("ACME_DYN_GET_AUTHORATATIVE_NAMESERVER"):
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
                metrics.send("get_authoritative_nameserver_error", "counter", 1)
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
    else:
        return "8.8.8.8"
