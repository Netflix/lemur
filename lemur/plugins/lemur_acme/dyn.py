import time

import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver
from dyn.tm.errors import DynectCreateError, DynectGetError
from dyn.tm.session import DynectSession
from dyn.tm.zones import Node, Zone, get_all_zones
from flask import current_app


def get_dynect_session():
    dynect_session = DynectSession(
        current_app.config.get('ACME_DYN_CUSTOMER_NAME', ''),
        current_app.config.get('ACME_DYN_USERNAME', ''),
        current_app.config.get('ACME_DYN_PASSWORD', ''),
    )
    return dynect_session


def _has_dns_propagated(name, token):
    txt_records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [get_authoritative_nameserver(name)]
        dns_response = dns_resolver.query(name, 'TXT')
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record.decode("utf-8"))
    except dns.exception.DNSException:
        return False

    for txt_record in txt_records:
        if txt_record == token:
            return True

    return False


def wait_for_dns_change(change_id, account_number=None):
    fqdn, token = change_id
    number_of_attempts = 10
    for attempts in range(0, number_of_attempts):
        status = _has_dns_propagated(fqdn, token)
        current_app.logger.debug("Record status for fqdn: {}: {}".format(fqdn, status))
        if status:
            break
        time.sleep(20)
    if not status:
        # TODO: Delete associated DNS text record here
        raise Exception("Unable to query DNS token for fqdn {}.".format(fqdn))
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
        raise Exception("No Dyn zone found for domain: {}".format(domain))
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
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)
    zone = Zone(zone_name)

    try:
        zone.add_record(node_name, record_type='TXT', txtdata="\"{}\"".format(token), ttl=5)
        zone.publish()
        current_app.logger.debug("TXT record created: {0}, token: {1}".format(fqdn, token))
    except DynectCreateError as e:
        if "Cannot duplicate existing record data" in e.message:
            current_app.logger.debug(
                "Unable to add record. Domain: {}. Token: {}. "
                "Record already exists: {}".format(domain, token, e), exc_info=True
            )
        else:
            raise

    change_id = (fqdn, token)
    return change_id


def delete_txt_record(change_id, account_number, domain, token):
    get_dynect_session()
    if not domain:
        current_app.logger.debug("delete_txt_record: No domain passed")
        return

    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)

    try:
        all_txt_records = node.get_all_records_by_type('TXT')
    except DynectGetError:
        # No Text Records remain or host is not in the zone anymore because all records have been deleted.
        return
    for txt_record in all_txt_records:
        if txt_record.txtdata == ("{}".format(token)):
            current_app.logger.debug("Deleting TXT record name: {0}".format(fqdn))
            txt_record.delete()
    zone.publish()


def delete_acme_txt_records(domain):
    get_dynect_session()
    if not domain:
        current_app.logger.debug("delete_acme_txt_records: No domain passed")
        return
    acme_challenge_string = "_acme-challenge"
    if not domain.startswith(acme_challenge_string):
        current_app.logger.debug(
            "delete_acme_txt_records: Domain {} doesn't start with string {}. "
            "Cowardly refusing to delete TXT records".format(domain, acme_challenge_string))
        return

    zone_name = get_zone_name(domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)

    all_txt_records = node.get_all_records_by_type('TXT')
    for txt_record in all_txt_records:
        current_app.logger.debug("Deleting TXT record name: {0}".format(fqdn))
        txt_record.delete()
    zone.publish()


def get_authoritative_nameserver(domain):
    if current_app.config.get('ACME_DYN_GET_AUTHORATATIVE_NAMESERVER'):
        n = dns.name.from_text(domain)

        depth = 2
        default = dns.resolver.get_default_resolver()
        nameserver = default.nameservers[0]

        last = False
        while not last:
            s = n.split(depth)

            last = s[0].to_unicode() == u'@'
            sub = s[1]

            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, nameserver)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    raise Exception('%s does not exist.' % sub)
                else:
                    raise Exception('Error %s' % dns.rcode.to_text(rcode))

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
