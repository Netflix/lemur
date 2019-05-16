"""
.. module: lemur.reporting.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from tabulate import tabulate
from flask_script import Manager

from lemur.reporting.service import fqdns, expiring_certificates

manager = Manager(usage="Reporting related tasks.")


@manager.option(
    "-v",
    "--validity",
    dest="validity",
    choices=["all", "expired", "valid"],
    default="all",
    help="Filter certificates by validity.",
)
@manager.option(
    "-d",
    "--deployment",
    dest="deployment",
    choices=["all", "deployed", "ready"],
    default="all",
    help="Filter by deployment status.",
)
def fqdn(deployment, validity):
    """
    Generates a report in order to determine the number of FQDNs covered by Lemur issued certificates.
    """
    headers = [
        "FQDN",
        "Root Domain",
        "Issuer",
        "Owner",
        "Validity End",
        "Total Length (days), Time Until Expiration (days)",
    ]
    rows = []

    for cert in fqdns(validity=validity, deployment=deployment).all():
        for domain in cert.domains:
            rows.append(
                [
                    domain.name,
                    ".".join(domain.name.split(".")[1:]),
                    cert.issuer,
                    cert.owner,
                    cert.not_after,
                    cert.validity_range.days,
                    cert.validity_remaining.days,
                ]
            )

    print(tabulate(rows, headers=headers))


@manager.option("-ttl", "--ttl", dest="ttl", default=30, help="Days til expiration.")
@manager.option(
    "-d",
    "--deployment",
    dest="deployment",
    choices=["all", "deployed", "ready"],
    default="all",
    help="Filter by deployment status.",
)
def expiring(ttl, deployment):
    """
    Returns certificates expiring in the next n days.
    """
    headers = ["Common Name", "Owner", "Issuer", "Validity End", "Endpoint"]
    rows = []

    for cert in expiring_certificates(ttl=ttl, deployment=deployment).all():
        for endpoint in cert.endpoints:
            rows.append(
                [cert.cn, cert.owner, cert.issuer, cert.not_after, endpoint.dnsname]
            )

    print(tabulate(rows, headers=headers))
