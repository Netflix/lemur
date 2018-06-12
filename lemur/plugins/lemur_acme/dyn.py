import time

import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver
from dyn.tm.errors import DynectCreateError
from dyn.tm.session import DynectSession
from dyn.tm.zones import Node, Zone
from flask import current_app
from tld import get_tld


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
    while True:
        status = _has_dns_propagated(fqdn, token)
        current_app.logger.debug("Record status for fqdn: {}: {}".format(fqdn, status))
        if status:
            break
        time.sleep(20)
    return


def create_txt_record(domain, token, account_number):
    get_dynect_session()
    zone_name = get_tld('http://' + domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)
    zone = Zone(zone_name)
    try:
        zone.add_record(node_name, record_type='TXT', txtdata="\"{}\"".format(token), ttl=5)
    except DynectCreateError:
        delete_txt_record(None, None, domain, token)
        zone.add_record(node_name, record_type='TXT', txtdata="\"{}\"".format(token), ttl=5)
    node = zone.get_node(node_name)
    zone.publish()
    current_app.logger.debug("TXT record created: {0}".format(fqdn))
    change_id = (fqdn, token)
    return change_id


def delete_txt_record(change_id, account_number, domain, token):
    get_dynect_session()
    if not domain:
        current_app.logger.debug("delete_txt_record: No domain passed")
        return

    zone_name = get_tld('http://' + domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)

    all_txt_records = node.get_all_records_by_type('TXT')
    for txt_record in all_txt_records:
        if txt_record.txtdata == ("{}".format(token)):
            current_app.logger.debug("Deleting TXT record name: {0}".format(fqdn))
            txt_record.delete()
    zone.publish()


def get_authoritative_nameserver(domain):
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
