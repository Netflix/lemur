"""
.. module: lemur.pending_certificates.cli

.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
"""

import click
import copy
import sys

from flask import current_app

from lemur.authorities.service import get as get_authority
from lemur.constants import ACME_ADDITIONAL_ATTEMPTS
from lemur.notifications.messaging import send_pending_failure_notification
from lemur.pending_certificates import service as pending_certificate_service
from lemur.plugins.base import plugins


@click.group(name="pending_certs", help="Handles pending certificate related tasks.")
def cli():
    pass


@cli.command("fetch")
@click.option(
    "-i",
    "ids",
    multiple=True,
    help="IDs of pending certificates to fetch"
)
def fetch_command(ids):
    fetch(ids)


def fetch(ids):
    """
    Attempt to get full certificate for each pending certificate listed.

    Args:
        ids: a list of ids of PendingCertificates (passed in by manager options when run as CLI)
             `python manager.py pending_certs fetch -i 123 321 all`
    """
    pending_certs = pending_certificate_service.get_pending_certs(ids)

    new = 0
    failed = 0

    for cert in pending_certs:
        authority = plugins.get(cert.authority.plugin_name)
        real_cert = authority.get_ordered_certificate(cert)
        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and mark
            # the pending certificate as resolved
            final_cert = pending_certificate_service.create_certificate(
                cert, real_cert, cert.user
            )
            pending_certificate_service.update(cert.id, resolved_cert_id=final_cert.id)
            pending_certificate_service.update(cert.id, resolved=True)
            # add metrics to metrics extension
            new += 1
        else:
            pending_certificate_service.increment_attempt(cert)
            failed += 1
    click.echo(
        f"[+] Certificates: New: {new} Failed: {failed}"
    )


@cli.command("fetch_all_acme")
def fetch_all_acme_command():
    fetch_all_acme()


def fetch_all_acme():
    """
    Attempt to get full certificates for each pending certificate listed with the acme-issuer. This is more efficient
    for acme-issued certificates because it will configure all of the DNS challenges prior to resolving any
    certificates.
    """

    log_data = {"function": f"{__name__}.{sys._getframe().f_code.co_name}"}
    pending_certs = pending_certificate_service.get_unresolved_pending_certs()
    new = 0
    failed = 0
    wrong_issuer = 0
    acme_certs = []

    # We only care about certs using the acme-issuer plugin
    for cert in pending_certs:
        cert_authority = get_authority(cert.authority_id)
        if cert_authority.plugin_name == "acme-issuer":
            acme_certs.append(cert)
        else:
            wrong_issuer += 1

    authority = plugins.get("acme-issuer")
    resolved_certs = authority.get_ordered_certificates(acme_certs)

    for cert in resolved_certs:
        real_cert = cert.get("cert")
        # It's necessary to reload the pending cert due to detached instance: http://sqlalche.me/e/bhk3
        pending_cert = pending_certificate_service.get(cert.get("pending_cert").id)

        if real_cert:
            # If a real certificate was returned from issuer, then create it in Lemur and mark
            # the pending certificate as resolved
            final_cert = pending_certificate_service.create_certificate(
                pending_cert, real_cert, pending_cert.user
            )
            pending_certificate_service.update(
                pending_cert.id, resolved_cert_id=final_cert.id
            )
            pending_certificate_service.update(pending_cert.id, resolved=True)
            # add metrics to metrics extension
            new += 1
        else:
            failed += 1
            error_log = copy.deepcopy(log_data)
            error_log["message"] = "Pending certificate creation failure"
            error_log["pending_cert_id"] = pending_cert.id
            error_log["last_error"] = cert.get("last_error")
            error_log["cn"] = pending_cert.cn

            if pending_cert.number_attempts > ACME_ADDITIONAL_ATTEMPTS:
                error_log["message"] = "Marking pending certificate as resolved"
                send_pending_failure_notification(
                    pending_cert, notify_owner=pending_cert.notify
                )
                # Mark "resolved" as True
                pending_certificate_service.update(cert.id, resolved=True)
            else:
                pending_certificate_service.increment_attempt(pending_cert)
                pending_certificate_service.update(
                    cert.get("pending_cert").id, status=str(cert.get("last_error"))
                )
            current_app.logger.error(error_log)
    log_data["message"] = "Complete"
    log_data["new"] = new
    log_data["failed"] = failed
    log_data["wrong_issuer"] = wrong_issuer
    current_app.logger.debug(log_data)
    click.echo(
        "[+] Certificates: New: {new} Failed: {failed} Not using ACME: {wrong_issuer}".format(
            new=new, failed=failed, wrong_issuer=wrong_issuer
        )
    )
