import sys
import dns
import dns.exception
import dns.name
import dns.query
import dns.resolver
import re
from sentry_sdk import capture_exception

from lemur.extensions import metrics


class DNSError(Exception):
    """Base class for DNS Exceptions."""
    pass


class BadDomainError(DNSError):
    """Error for when a Bad Domain Name is given."""

    def __init__(self, message):
        self.message = message


class DNSResolveError(DNSError):
    """Error for DNS Resolution Errors."""

    def __init__(self, message):
        self.message = message


def is_valid_domain(domain):
    """Checks if a domain is syntactically valid and returns a bool"""
    if domain[-1] == ".":
        domain = domain[:-1]
    if len(domain) > 253:
        return False
    fqdn_re = re.compile("(?=^.{1,63}$)(^(?:[a-z0-9_](?:-*[a-z0-9_])+)$|^[a-z0-9]$)", re.IGNORECASE)
    return all(fqdn_re.match(d) for d in domain.split("."))


def get_authoritative_nameserver(domain):
    """Get the authoritative nameservers for the given domain"""
    if not is_valid_domain(domain):
        raise BadDomainError(f"{domain} is not a valid FQDN")

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
                raise DNSResolveError(f"{sub} does not exist.")
            else:
                raise DNSResolveError(f"Error: {dns.rcode.to_text(rcode)}")

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


def get_dns_records(domain, rdtype, nameserver):
    """Retrieves the DNS records matching the name and type and returns a list of records"""
    records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [nameserver]
        dns_response = dns_resolver.query(domain, rdtype)
        for rdata in dns_response:
            for record in rdata.strings:
                records.append(record.decode("utf-8"))
    except dns.exception.DNSException:
        capture_exception()
        function = sys._getframe().f_code.co_name
        metrics.send(f"{function}.fail", "counter", 1)
    return records
