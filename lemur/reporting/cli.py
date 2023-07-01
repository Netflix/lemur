"""
.. module: lemur.reporting.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import click

from tabulate import tabulate

from lemur.reporting.service import fqdns, expiring_certificates


@click.group(name="report", help="Reporting related tasks.")
def cli():
    pass


@cli.command("fqdn")
@click.option(
    "-v",
    "--validity",
    "validity",
    type=click.Choice(["all", "expired", "valid"], case_sensitive=False),
    default="all",
    help="Filter certificates by validity.",
)
@click.option(
    "-d",
    "--deployment",
    "deployment",
    type=click.Choice(["all", "deployed", "ready"], case_sensitive=False),
    default="all",
    help="Filter by deployment status.",
)
def fqdn_command(deployment, validity):
    fqdn(deployment, validity)


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

    click.echo(tabulate(rows, headers=headers))


@cli.command("expiring")
@click.option("-ttl",
              "--ttl",
              "ttl",
              default=30,
              help="Days til expiration."
)
@click.option(
    "-d",
    "--deployment",
    "deployment",
    type=click.Choice(["all", "deployed", "ready"], case_sensitive=False),
    default="all",
    help="Filter by deployment status.",
)
def expiring_command(ttl, deployment):
    expiring(ttl, deployment)


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

    click.echo(tabulate(rows, headers=headers))
