"""
.. module: lemur.certificate.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
import sys
import click

from flask import current_app
from flask_principal import Identity, identity_changed
from sqlalchemy import or_
from tabulate import tabulate
from time import sleep
from sentry_sdk import capture_exception

from lemur import database
from lemur.authorities.models import Authority
from lemur.authorities.service import get as authorities_get_by_id
from lemur.authorities.service import get_by_name as get_authority_by_name
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import CertificateOutputSchema
from lemur.certificates.service import (
    reissue_certificate,
    get_certificate_primitives,
    get_all_pending_reissue,
    get_by_name,
    get_all_valid_certs,
    get,
    get_all_certs_attached_to_endpoint_without_autorotate,
    get_all_certs_attached_to_destination_without_autorotate,
    revoke as revoke_certificate,
    list_recent_valid_certs_issued_by_authority,
    get_certificates_with_same_cn_with_rotate_on,
    identify_and_persist_expiring_deployed_certificates,
    send_certificate_expiration_metrics
)
from lemur.certificates.verify import verify_string
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS, CRLReason
from lemur.deployment import service as deployment_service
from lemur.domains.models import Domain
from lemur.endpoints import service as endpoint_service
from lemur.extensions import metrics
from lemur.notifications.messaging import send_rotation_notification, send_reissue_no_endpoints_notification, \
    send_reissue_failed_notification
from lemur.plugins.base import plugins
from sqlalchemy.orm.exc import MultipleResultsFound


@click.group(name="certificates", help="Handles all certificate related tasks.")
def cli():
    pass


def print_certificate_details(details):
    """
    Print the certificate details with formatting.
    :param details:
    :return:
    """
    details, errors = CertificateOutputSchema().dump(details)
    click.echo("[+] Re-issuing certificate with the following details: ")
    click.echo(
        "\t[+] Common Name: {common_name}\n"
        "\t[+] Subject Alternate Names: {sans}\n"
        "\t[+] Authority: {authority_name}\n"
        "\t[+] Validity Start: {validity_start}\n"
        "\t[+] Validity End: {validity_end}\n".format(
            common_name=details["commonName"],
            sans=",".join(
                x["value"] for x in details["extensions"]["subAltNames"]["names"]
            )
            or None,
            authority_name=details["authority"]["name"],
            validity_start=details["validityStart"],
            validity_end=details["validityEnd"],
        )
    )


def validate_certificate(certificate_name):
    """
    Ensuring that the specified certificate exists.
    :param certificate_name:
    :return:
    """
    if certificate_name:
        cert = get_by_name(certificate_name)

        if not cert:
            click.echo(f"[-] No certificate found with name: {certificate_name}")
            sys.exit(1)

        return cert


def validate_endpoint(endpoint_name):
    """
    Ensuring that the specified endpoint exists.
    :param endpoint_name:
    :return:
    """
    if endpoint_name:
        endpoint = endpoint_service.get_by_name(endpoint_name)

        if not endpoint:
            click.echo(f"[-] No endpoint found with name: {endpoint_name}")
            sys.exit(1)

        return endpoint


def validate_endpoint_from_source(endpoint_name, source):
    """
    Ensuring that the specified endpoint from the given source exists.
    :param endpoint_name:
    :param source:
    :return:
    """
    if endpoint_name and source:
        endpoint = endpoint_service.get_by_name_and_source(endpoint_name, source)

        if not endpoint:
            click.echo(f"[-] No endpoint found from source {source} with name: {endpoint_name}")
            sys.exit(1)

        return endpoint


def request_rotation(endpoint, certificate, message, commit):
    """
    Rotates a certificate and handles any exceptions during
    execution.
    :param endpoint:
    :param certificate:
    :param message:
    :param commit:
    :return:
    """
    status = FAILURE_METRIC_STATUS
    if commit:
        try:
            deployment_service.rotate_certificate(endpoint, certificate)

            if message:
                send_rotation_notification(certificate)

            status = SUCCESS_METRIC_STATUS

        except Exception as e:
            capture_exception(extra={"certificate_name": str(certificate.name),
                                     "endpoint": str(endpoint.dnsname)})
            current_app.logger.exception(
                f"Error rotating certificate: {certificate.name}", exc_info=True
            )
            click.echo(
                "[!] Failed to rotate endpoint {} to certificate {} reason: {}".format(
                    endpoint.name, certificate.name, e
                )
            )

    metrics.send("endpoint_rotation", "counter", 1, metric_tags={"status": status,
                                                                 "certificate_name": str(certificate.name),
                                                                 "endpoint": str(endpoint.dnsname)})


def request_reissue(certificate, notify, commit):
    """
    Reissuing certificate and handles any exceptions.
    :param certificate:
    :param notify:
    :param commit:
    :return:
    """
    status = FAILURE_METRIC_STATUS
    notify = notify and certificate.notify
    try:
        click.echo(f"[+] {certificate.name} is eligible for re-issuance")

        # set the lemur identity for all cli commands
        identity_changed.send(current_app._get_current_object(), identity=Identity(1))

        details = get_certificate_primitives(certificate)
        print_certificate_details(details)

        if commit:
            new_cert = reissue_certificate(certificate, notify=notify, replace=True)
            click.echo(f"[+] New certificate named: {new_cert.name}")
            if notify and isinstance(new_cert, Certificate):  # let celery handle PendingCertificates
                send_reissue_no_endpoints_notification(certificate, new_cert)

        status = SUCCESS_METRIC_STATUS

    except Exception as e:
        capture_exception(extra={"certificate_name": str(certificate.name)})
        current_app.logger.exception(
            f"Error reissuing certificate: {certificate.name}", exc_info=True
        )
        click.echo(f"[!] Failed to reissue certificate: {certificate.name}. Reason: {e}")
        if notify:
            send_reissue_failed_notification(certificate)

    metrics.send(
        "certificate_reissue",
        "counter",
        1,
        metric_tags={"status": status, "certificate": certificate.name},
    )


@click.option(
    "-e",
    "--endpoint",
    "endpoint_name",
    help="Name of the endpoint you wish to rotate.",
)
@click.option(
    "-s",
    "--source",
    "source",
    help="Source of the endpoint you wish to rotate.",
)
@click.option(
    "-n",
    "--new-certificate",
    "new_certificate_name",
    help="Name of the certificate you wish to rotate to.",
)
@click.option(
    "-o",
    "--old-certificate",
    "old_certificate_name",
    help="Name of the certificate you wish to rotate.",
)
@click.option(
    "-a",
    "--notify",
    "message",
    type=bool,
    default=False,
    help="Send a rotation notification to the certificates owner.",
)
@click.option(
    "-c",
    "--commit",
    "commit",
    type=bool,
    default=False,
    help="Persist changes.",
)
def rotate_command(endpoint_name, source, new_certificate_name, old_certificate_name, message, commit):
    rotate(endpoint_name, source, new_certificate_name, old_certificate_name, message, commit)


def rotate(endpoint_name, source, new_certificate_name, old_certificate_name, message, commit):
    """
    Rotates an endpoint and reissues it if it has not already been replaced. If it has
    been replaced, will use the replacement certificate for the rotation.
    """
    if commit:
        click.echo("[!] Running in COMMIT mode.")

    click.echo("[+] Starting endpoint rotation.")

    status = FAILURE_METRIC_STATUS

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
    }

    try:
        old_cert = validate_certificate(old_certificate_name)
        new_cert = validate_certificate(new_certificate_name)
        if source:
            endpoint = validate_endpoint_from_source(endpoint_name, source)
        else:
            try:
                endpoint = validate_endpoint(endpoint_name)
            except MultipleResultsFound as e:
                click.echo(f"[!] Multiple endpoints found with name {endpoint_name}, try narrowing the search down to an endpoint from a specific source by re-running this command with the --source flag.")
                log_data["message"] = "Multiple endpoints found with same name, unable to perform rotation"
                log_data["duplicated_endpoint_name"] = endpoint_name
                current_app.logger.info(log_data)
                raise

        if endpoint and new_cert:
            click.echo(
                f"[+] Rotating endpoint: {endpoint.name} to certificate {new_cert.name}"
            )
            log_data["message"] = "Rotating one endpoint"
            log_data["endpoint"] = endpoint.dnsname
            log_data["certificate"] = new_cert.name
            request_rotation(endpoint, new_cert, message, commit)
            current_app.logger.info(log_data)

        elif old_cert and new_cert:
            click.echo(f"[+] Rotating all endpoints from {old_cert.name} to {new_cert.name}")
            log_data["certificate"] = new_cert.name
            log_data["certificate_old"] = old_cert.name
            log_data["message"] = "Rotating endpoint from old to new cert"
            for endpoint in old_cert.endpoints:
                click.echo(f"[+] Rotating {endpoint.name}")
                log_data["endpoint"] = endpoint.dnsname
                request_rotation(endpoint, new_cert, message, commit)
                current_app.logger.info(log_data)

        else:
            # No certificate name or endpoint is provided. We will now fetch all endpoints,
            # which are associated with a certificate that has been replaced
            click.echo("[+] Rotating all endpoints that have new certificates available")
            for endpoint in endpoint_service.get_all_pending_rotation():

                log_data["message"] = "Rotating endpoint from old to new cert"
                if len(endpoint.certificate.replaced) > 1:
                    log_data["message"] = f"Multiple replacement certificates found, going with the first one out of " \
                                          f"{len(endpoint.certificate.replaced)}"

                log_data["endpoint"] = endpoint.dnsname
                log_data["certificate"] = endpoint.certificate.replaced[0].name
                click.echo(
                    f"[+] Rotating {endpoint.name} to {endpoint.certificate.replaced[0].name}"
                )
                request_rotation(endpoint, endpoint.certificate.replaced[0], message, commit)
                current_app.logger.info(log_data)

        status = SUCCESS_METRIC_STATUS
        click.echo("[+] Done!")

    except Exception as e:
        capture_exception(
            extra={
                "old_certificate_name": str(old_certificate_name),
                "new_certificate_name": str(new_certificate_name),
                "endpoint_name": str(endpoint_name),
                "message": str(message),
            }
        )

    metrics.send(
        "endpoint_rotation_job",
        "counter",
        1,
        metric_tags={
            "status": status,
            "old_certificate_name": str(old_certificate_name),
            "new_certificate_name": str(new_certificate_name),
            "endpoint_name": str(endpoint_name),
            "message": str(message),
            "endpoint": str(globals().get("endpoint")),
        },
    )


def request_rotation_region(endpoint, new_cert, message, commit, log_data, region):
    if region in endpoint.dnsname:
        log_data["message"] = "Rotating endpoint in region"
        request_rotation(endpoint, new_cert, message, commit)
    else:
        log_data["message"] = "Skipping rotation, region mismatch"

    click.echo(log_data)
    current_app.logger.info(log_data)


@cli.command("rotate_region")
@click.option(
    "-e",
    "--endpoint",
    "endpoint_name",
    help="Name of the endpoint you wish to rotate.",
)
@click.option(
    "-n",
    "--new-certificate",
    "new_certificate_name",
    help="Name of the certificate you wish to rotate to.",
)
@click.option(
    "-o",
    "--old-certificate",
    "old_certificate_name",
    help="Name of the certificate you wish to rotate.",
)
@click.option(
    "-a",
    "--notify",
    "message",
    type=bool,
    default=False,
    help="Send a rotation notification to the certificates owner.",
)
@click.option(
    "-c",
    "--commit",
    "commit",
    type=bool,
    default=False,
    help="Persist changes.",
)
@click.option(
    "-r",
    "--region",
    "region",
    required=True,
    help="Region in which to rotate the endpoint.",
)
def rotate_region_command(endpoint_name, new_certificate_name, old_certificate_name, message, commit, region):
    rotate_region(endpoint_name, new_certificate_name, old_certificate_name, message, commit, region)


def rotate_region(endpoint_name, new_certificate_name, old_certificate_name, message, commit, region):
    """
    Rotates an endpoint in a defined region it if it has not already been replaced. If it has
    been replaced, will use the replacement certificate for the rotation.
    :param old_certificate_name: Name of the certificate you wish to rotate.
    :param new_certificate_name: Name of the certificate you wish to rotate to.
    :param endpoint_name: Name of the endpoint you wish to rotate.
    :param message: Send a rotation notification to the certificates owner.
    :param commit: Persist changes.
    :param region: Region in which to rotate the endpoint.
    #todo: merge this method with rotate()
    """
    if commit:
        click.echo("[!] Running in COMMIT mode.")

    click.echo("[+] Starting endpoint rotation.")
    status = FAILURE_METRIC_STATUS

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "region": region,
    }

    try:
        old_cert = validate_certificate(old_certificate_name)
        new_cert = validate_certificate(new_certificate_name)
        endpoint = validate_endpoint(endpoint_name)

        if endpoint and new_cert:
            log_data["endpoint"] = endpoint.dnsname
            log_data["certificate"] = new_cert.name
            request_rotation_region(endpoint, new_cert, message, commit, log_data, region)

        elif old_cert and new_cert:
            log_data["certificate"] = new_cert.name
            log_data["certificate_old"] = old_cert.name
            log_data["message"] = "Rotating endpoint from old to new cert"
            click.echo(log_data)
            current_app.logger.info(log_data)
            for endpoint in old_cert.endpoints:
                log_data["endpoint"] = endpoint.dnsname
                request_rotation_region(endpoint, new_cert, message, commit, log_data, region)

        else:
            log_data["message"] = "Rotating all endpoints that have new certificates available"
            click.echo(log_data)
            current_app.logger.info(log_data)
            all_pending_rotation_endpoints = endpoint_service.get_all_pending_rotation()
            for endpoint in all_pending_rotation_endpoints:
                log_data["endpoint"] = endpoint.dnsname
                if region not in endpoint.dnsname:
                    log_data["message"] = "Skipping rotation, region mismatch"
                    click.echo(log_data)
                    current_app.logger.info(log_data)
                    metrics.send(
                        "endpoint_rotation_region_skipped",
                        "counter",
                        1,
                        metric_tags={
                            "region": region,
                            "new_certificate_name": str(endpoint.certificate.replaced[0].name),
                            "endpoint_name": str(endpoint.dnsname),
                        },
                    )
                    continue

                log_data["certificate"] = endpoint.certificate.replaced[0].name
                log_data["message"] = "Rotating all endpoints in region"
                if len(endpoint.certificate.replaced) > 1:
                    log_data["message"] = f"Multiple replacement certificates found, going with the first one out of " \
                                          f"{len(endpoint.certificate.replaced)}"

                request_rotation(endpoint, endpoint.certificate.replaced[0], message, commit)
                current_app.logger.info(log_data)

                metrics.send(
                    "endpoint_rotation_region",
                    "counter",
                    1,
                    metric_tags={
                        "status": FAILURE_METRIC_STATUS,
                        "new_certificate_name": str(log_data["certificate"]),
                        "endpoint_name": str(endpoint.dnsname),
                        "message": str(message),
                        "region": str(region),
                    },
                )
        status = SUCCESS_METRIC_STATUS
        click.echo("[+] Done!")

    except Exception as e:
        capture_exception(
            extra={
                "old_certificate_name": str(old_certificate_name),
                "new_certificate_name": str(new_certificate_name),
                "endpoint": str(endpoint_name),
                "message": str(message),
                "region": str(region),
            }
        )

    metrics.send(
        "endpoint_rotation_region_job",
        "counter",
        1,
        metric_tags={
            "status": status,
            "old_certificate_name": str(old_certificate_name),
            "new_certificate_name": str(new_certificate_name),
            "endpoint_name": str(endpoint_name),
            "message": str(message),
            "endpoint": str(globals().get("endpoint")),
            "region": str(region),
        },
    )


@cli.command("reissue")
@click.option(
    "-o",
    "--old-certificate",
    "old_certificate_name",
    help="Name of the certificate you wish to reissue.",
)
@click.option(
    "-a",
    "--notify",
    "notify",
    type=bool,
    default=False,
    help="Send a re-issue failed notification to the certificates owner (if re-issuance fails).",
)
@click.option(
    "-c",
    "--commit",
    "commit",
    type=bool,
    default=False,
    help="Persist changes.",
)
def reissue_command(old_certificate_name, notify, commit):
    reissue(old_certificate_name, notify, commit)


def reissue(old_certificate_name, notify, commit):
    """
    Reissues certificate with the same parameters as it was originally issued with.
    If not time period is provided, reissues certificate as valid from today to
    today + length of original.
    """
    if commit:
        click.echo("[!] Running in COMMIT mode.")

    click.echo("[+] Starting certificate re-issuance.")

    status = FAILURE_METRIC_STATUS

    try:
        old_cert = validate_certificate(old_certificate_name)

        if not old_cert:
            for certificate in get_all_pending_reissue():
                request_reissue(certificate, notify, commit)
        else:
            request_reissue(old_cert, notify, commit)

        status = SUCCESS_METRIC_STATUS
        click.echo("[+] Done!")
    except Exception as e:
        capture_exception()
        current_app.logger.exception("Error reissuing certificate.", exc_info=True)
        click.echo(f"[!] Failed to reissue certificates. Reason: {e}")

    metrics.send(
        "certificate_reissue_job", "counter", 1, metric_tags={"status": status}
    )


@cli.command("query")
@click.option(
    "-f",
    "--fqdns",
    "fqdns",
    help="FQDNs to query. Multiple fqdns specified via comma.",
)
@click.option("-i", "--issuer", "issuer", help="Issuer to query for.")
@click.option("-o", "--owner", "owner", help="Owner to query for.")
@click.option(
    "-e",
    "--expired",
    "expired",
    type=bool,
    default=False,
    help="Include expired certificates.",
)
def query_command(fqdns, issuer, owner, expired):
    query(fqdns, issuer, owner, expired)


def query(fqdns, issuer, owner, expired):
    """Prints certificates that match the query params."""
    table = []

    q = database.session_query(Certificate)
    if issuer:
        sub_query = (
            database.session_query(Authority.id)
            .filter(Authority.name.ilike(f"%{issuer}%"))
            .subquery()
        )

        q = q.filter(
            or_(
                Certificate.issuer.ilike(f"%{issuer}%"),
                Certificate.authority_id.in_(sub_query),
            )
        )
    if owner:
        q = q.filter(Certificate.owner.ilike(f"%{owner}%"))

    if not expired:
        q = q.filter(Certificate.expired == False)  # noqa

    if fqdns:
        for f in fqdns.split(","):
            q = q.filter(
                or_(
                    Certificate.cn.ilike(f"%{f}%"),
                    Certificate.domains.any(Domain.name.ilike(f"%{f}%")),
                )
            )

    for c in q.all():
        table.append([c.id, c.name, c.owner, c.issuer])

    click.echo(tabulate(table, headers=["Id", "Name", "Owner", "Issuer"], tablefmt="csv"))


def worker(data, commit, reason):
    parts = [x for x in data.split(" ") if x]
    try:
        cert = get(int(parts[0].strip()))

        click.echo(f"[+] Revoking certificate. Id: {cert.id} Name: {cert.name}")
        if commit:
            revoke_certificate(cert, reason)

        metrics.send(
            "certificate_revoke",
            "counter",
            1,
            metric_tags={"status": SUCCESS_METRIC_STATUS},
        )

    except Exception as e:
        capture_exception()
        metrics.send(
            "certificate_revoke",
            "counter",
            1,
            metric_tags={"status": FAILURE_METRIC_STATUS},
        )
        click.echo(f"[!] Failed to revoke certificates. Reason: {e}")


@cli.command("clear_pending")
def clear_pending_command():
    clear_pending()


def clear_pending():
    """
    Function clears all pending certificates.
    :return:
    """
    v = plugins.get("verisign-issuer")
    v.clear_pending_certificates()


@cli.command("revoke")
@click.option("-p", "--path", "path", help="Absolute file path to a Lemur query csv.")
@click.option("-id", "--certid", "cert_id", help="ID of the certificate to be revoked")
@click.option("-r", "--reason", "reason", default="unspecified", help="CRL Reason as per RFC 5280 section 5.3.1")
@click.option("-m", "--message", "message", help="Message explaining reason for revocation")
@click.option(
    "-c",
    "--commit",
    "commit",
    type=bool,
    default=False,
    help="Persist changes.",
)
def revoke_command(path, cert_id, reason, message, commit):
    revoke(path, cert_id, reason, message, commit)


def revoke(path, cert_id, reason, message, commit):
    """
    Revokes given certificate.
    """
    if not path and not cert_id:
        click.echo("[!] No input certificates mentioned to revoke")
        return
    if path and cert_id:
        click.echo("[!] Please mention single certificate id (-id) or input file (-p)")
        return

    if commit:
        click.echo("[!] Running in COMMIT mode.")

    click.echo("[+] Starting certificate revocation.")

    if reason not in CRLReason.__members__:
        reason = CRLReason.unspecified.name
    comments = {"comments": message, "crl_reason": reason}

    if cert_id:
        worker(cert_id, commit, comments)
    else:
        with open(path) as f:
            for x in f.readlines()[2:]:
                worker(x, commit, comments)


@cli.command("check_revoked")
def check_revoked_command():
    check_revoked()


def check_revoked():
    """
    Function attempts to update Lemur's internal cache with revoked
    certificates. This is called periodically by Lemur. It checks both
    CRLs and OCSP to see if a certificate is revoked. If Lemur is unable
    encounters an issue with verification it marks the certificate status
    as `unknown`.
    """

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Checking for revoked Certificates"
    }
    there_are_still_certs = True
    page = 1
    count = 1000
    ocsp_err_count = 0
    crl_err_count = 0
    while there_are_still_certs:
        # get all valid certs issued until day before. This is to avoid OCSP not knowing about a newly created cert.
        certs = get_all_valid_certs(current_app.config.get("SUPPORTED_REVOCATION_AUTHORITY_PLUGINS", []),
                                    paginate=True, page=page, count=count,
                                    created_on_or_before=arrow.now().shift(days=-1))
        if len(certs) < count:
            # this must be tha last page
            there_are_still_certs = False
        else:
            metrics.send(
                "certificate_revoked_progress",
                "counter",
                1,
                metric_tags={"page": page}
            )
            page += 1

        for cert in certs:
            try:
                if cert.chain:
                    status, ocsp_err, crl_err = verify_string(cert.body, cert.chain)
                else:
                    status, ocsp_err, crl_err = verify_string(cert.body, "")

                ocsp_err_count += ocsp_err
                crl_err_count += crl_err

                if status is None:
                    cert.status = "unknown"
                else:
                    cert.status = "valid" if status else "revoked"

                if cert.status == "revoked":
                    log_data["valid"] = cert.status
                    log_data["certificate_name"] = cert.name
                    log_data["certificate_id"] = cert.id
                    metrics.send(
                        "certificate_revoked",
                        "counter",
                        1,
                        metric_tags={"status": log_data["valid"],
                                 "certificate_name": log_data["certificate_name"],
                                 "certificate_id": log_data["certificate_id"]},
                    )
                    current_app.logger.info(log_data)

            except Exception as e:
                capture_exception()
                current_app.logger.warning(e)
                cert.status = "unknown"

            try:
                database.update(cert)
            except Exception as e:
                capture_exception()
                current_app.logger.warning(e)

    metrics.send(
        "certificate_revoked_ocsp_error",
        "gauge",
        ocsp_err_count,
    )
    metrics.send(
        "certificate_revoked_crl_error",
        "gauge",
        crl_err_count,
    )
    metrics.send(
        "certificate_revoked_checked",
        "gauge",
        (page - 1) * count + len(certs),
    )


@cli.command("automatically_enable_autorotate_with_endpoint")
def automatically_enable_autorotate_with_endpoint_command():
    automatically_enable_autorotate_with_endpoint()


def automatically_enable_autorotate_with_endpoint():
    """
    This function automatically enables auto-rotation for unexpired certificates that are
    attached to an endpoint but do not have autorotate enabled.

    WARNING: This will overwrite the Auto-rotate toggle!
    """
    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Enabling auto-rotate for certificate"
    }

    permitted_authorities = current_app.config.get("ENABLE_AUTO_ROTATE_AUTHORITY", [])

    eligible_certs = get_all_certs_attached_to_endpoint_without_autorotate()
    for cert in eligible_certs:

        if cert.authority_id not in permitted_authorities:
            continue

        log_data["certificate"] = cert.name
        log_data["certificate_id"] = cert.id
        log_data["authority_id"] = cert.authority_id
        log_data["authority_name"] = authorities_get_by_id(cert.authority_id).name
        if cert.destinations:
            log_data["destination_names"] = ', '.join([d.label for d in cert.destinations])
        else:
            log_data["destination_names"] = "NONE"
        current_app.logger.info(log_data)
        metrics.send("automatically_enable_autorotate_with_endpoint",
                     "counter", 1,
                     metric_tags={"certificate": log_data["certificate"],
                                  "certificate_id": log_data["certificate_id"],
                                  "authority_id": log_data["authority_id"],
                                  "authority_name": log_data["authority_name"],
                                  "destination_names": log_data["destination_names"]
                                  })
        cert.rotation = True
        database.update(cert)


@cli.command("automatically_enable_autorotate_with_destination")
def automatically_enable_autorotate_with_destination_command():
    automatically_enable_autorotate_with_destination()


def automatically_enable_autorotate_with_destination():
    """
    This function automatically enables auto-rotation for unexpired certificates that are
    attached to a destination but do not have autorotate enabled.

    WARNING: This will overwrite the Auto-rotate toggle!
    """
    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Enabling auto-rotate for certificate"
    }

    permitted_authorities = current_app.config.get("ENABLE_AUTO_ROTATE_AUTHORITY", [])
    destination_plugin_name = current_app.config.get("ENABLE_AUTO_ROTATE_DESTINATION_TYPE", None)

    eligible_certs = get_all_certs_attached_to_destination_without_autorotate(plugin_name=destination_plugin_name)
    for cert in eligible_certs:

        if cert.authority_id not in permitted_authorities:
            continue

        log_data["certificate"] = cert.name
        log_data["certificate_id"] = cert.id
        log_data["authority_id"] = cert.authority_id
        log_data["authority_name"] = authorities_get_by_id(cert.authority_id).name
        if cert.destinations:
            log_data["destination_names"] = ', '.join([d.label for d in cert.destinations])
        else:
            log_data["destination_names"] = "NONE"
        current_app.logger.info(log_data)
        metrics.send("automatically_enable_autorotate_with_destination",
                     "counter", 1,
                     metric_tags={"certificate": log_data["certificate"],
                                  "certificate_id": log_data["certificate_id"],
                                  "authority_id": log_data["authority_id"],
                                  "authority_name": log_data["authority_name"],
                                  "destination_names": log_data["destination_names"]
                                  })
        cert.rotation = True
        database.update(cert)


@cli.command("deactivate_entrust_certificates")
def deactivate_entrust_certificates_command():
    deactivate_entrust_certificates()


def deactivate_entrust_certificates():
    """
    Attempt to deactivate test certificates issued by Entrust
    """

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Deactivating Entrust certificates"
    }

    certificates = get_all_valid_certs(['entrust-issuer'])
    entrust_plugin = plugins.get('entrust-issuer')
    for index, cert in enumerate(certificates):
        if (index % 10) == 0:
            # Entrust enforces a 10 request per 30s rate limit
            sleep(30)
        try:
            response = entrust_plugin.deactivate_certificate(cert)
            if response == 200:
                cert.status = "revoked"
            else:
                cert.status = "unknown"

            log_data["valid"] = cert.status
            log_data["certificate_name"] = cert.name
            log_data["certificate_id"] = cert.id
            metrics.send(
                "certificate_deactivate",
                "counter",
                1,
                metric_tags={"status": log_data["valid"],
                             "certificate_name": log_data["certificate_name"],
                             "certificate_id": log_data["certificate_id"]},
            )
            current_app.logger.info(log_data)

            database.update(cert)

        except Exception as e:
            current_app.logger.info(log_data)
            capture_exception()
            current_app.logger.exception(e)


@cli.command("disable_rotation_of_duplicate_certificates")
@click.option("-c", "--commit", "commit", type=bool, default=False, help="Persist changes.")
def disable_rotation_of_duplicate_certificates_command(commit):
    disable_rotation_of_duplicate_certificates(commit)


def disable_rotation_of_duplicate_certificates(commit):
    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Disabling auto-rotate for duplicate certificates"
    }

    if commit:
        click.echo("[!] Running in COMMIT mode.")

    authority_names = current_app.config.get("AUTHORITY_TO_DISABLE_ROTATE_OF_DUPLICATE_CERTIFICATES")
    if not authority_names:
        log_data["message"] = "Skipping task: No authorities configured"
        current_app.logger.debug(log_data)
        return

    log_data["authorities"] = authority_names
    days_since_issuance = current_app.config.get("DAYS_SINCE_ISSUANCE_DISABLE_ROTATE_OF_DUPLICATE_CERTIFICATES", None)
    log_data["days_since_issuance"] = f"{days_since_issuance} (Ignored if none)"

    authority_ids = []
    invalid_authorities = []
    for authority_name in authority_names:
        authority = get_authority_by_name(authority_name)
        if authority:
            authority_ids.append(authority.id)
        else:
            invalid_authorities.append(authority_name)

    if invalid_authorities:
        log_data["warning"] = f"Non-existing authorities: {invalid_authorities}"
    if not authority_ids:
        log_data["message"] = "Skipping task: No valid authorities configured"
        current_app.logger.error(log_data)
        return

    duplicate_candidate_certs = list_recent_valid_certs_issued_by_authority(authority_ids, days_since_issuance)

    log_data["duplicate_candidate_certs_count"] = len(duplicate_candidate_certs)
    current_app.logger.info(log_data)

    skipped_certs = []
    rotation_disabled_certs = []
    unique_common_names = []
    failed_certs = []

    for duplicate_candidate_cert in duplicate_candidate_certs:
        success, duplicates = process_duplicates(duplicate_candidate_cert,
                                                 days_since_issuance,
                                                 skipped_certs,
                                                 rotation_disabled_certs,
                                                 unique_common_names,
                                                 commit
                                                 )
        if not success:
            for cert in duplicates:
                failed_certs.append(cert.name)
                metrics.send("disable_rotation_duplicates", "counter", 1,
                             metric_tags={"status": "failed", "certificate": cert.name}
                             )

    # certs_with_serial_number_count + unique_common_names_count should be equal to
    # rotation_disabled_cert_count + rotation_disabled_cert_count + failed_to_determine_if_duplicate_count
    log_data["message"] = "Summary of task run"
    log_data["unique_common_names_count"] = len(unique_common_names)
    log_data["rotation_disabled_cert_count"] = len(rotation_disabled_certs)
    log_data["certificate_with_no_change_count"] = len(skipped_certs)
    log_data["failed_to_determine_if_duplicate_count"] = len(failed_certs)

    current_app.logger.info(log_data)


def process_duplicates(duplicate_candidate_cert, days_since_issuance, skipped_certs, rotation_disabled_certs, processed_unique_cn, commit):
    """
    Process duplicate_candidate_cert to see if there are more certs with exact same details (logic in `is_duplicate()`).
    If Yes, turn off auto


    :param duplicate_candidate_cert: Name of the certificate which has duplicates
    :param days_since_issuance: If not none, include certificates issued in only last days_since_issuance days
    :param skipped_certs: List of certificates which will continue to have rotation on (no change)
    :param rotation_disabled_certs: List of certificates for which rotation got disabled as part of this job
    :param processed_unique_cn: List of unique common names to avoid rework
    :return: Success - True or False; If False, set of duplicates which were not processed
    """
    if duplicate_candidate_cert.cn in processed_unique_cn:
        return True, None

    processed_unique_cn.append(duplicate_candidate_cert.cn)

    certs_with_same_cn = get_certificates_with_same_cn_with_rotate_on(duplicate_candidate_cert.cn,
                                                                      duplicate_candidate_cert.date_created)

    if len(certs_with_same_cn) == 1:
        # this is the only cert with rotation ON, no further action needed
        skipped_certs.append(certs_with_same_cn[0].name)
        metrics.send("disable_rotation_duplicates", "counter", 1,
                     metric_tags={"status": "skipped", "certificate": certs_with_same_cn[0].name}
                     )
        return True, None

    skip_cert = False
    certs_to_stay_on_autorotate = []

    for matching_cert in certs_with_same_cn:
        if matching_cert.name == duplicate_candidate_cert.name:
            # Same cert, no need to compare
            continue

        # Even if one of the certs has different details, skip this set of certs
        # It's safe to do so and this logic can be revisited
        if not is_duplicate(matching_cert, duplicate_candidate_cert):
            skip_cert = True
            break

        # If cert is attached to an endpoint, auto-rotate needs to stay ON
        if matching_cert.endpoints:
            certs_to_stay_on_autorotate.append(matching_cert.name)

    if skip_cert:
        # Not reporting failure for skipping cert since they are not duplicates,
        # comparision is working as intended
        for skipped_cert in certs_with_same_cn:
            skipped_certs.append(skipped_cert.name)
            metrics.send("disable_rotation_duplicates", "counter", 1,
                         metric_tags={"status": "skipped", "certificate": skipped_cert.name}
                         )
        return True, None

    # If no certificate has endpoint, allow autorotaion of only input duplicate_candidate_cert
    if not certs_to_stay_on_autorotate:
        certs_to_stay_on_autorotate.append(duplicate_candidate_cert.name)

    for matching_cert in certs_with_same_cn:
        if matching_cert.name in certs_to_stay_on_autorotate:
            skipped_certs.append(matching_cert.name)
            metrics.send("disable_rotation_duplicates", "counter", 1,
                         metric_tags={"status": "skipped", "certificate": matching_cert.name}
                         )
        else:
            # disable rotation and update DB
            matching_cert.rotation = False
            if commit:
                database.update(matching_cert)
            rotation_disabled_certs.append(matching_cert.name)
            metrics.send("disable_rotation_duplicates", "counter", 1,
                         metric_tags={"status": "success", "certificate": matching_cert.name}
                         )
    return True, None


def is_duplicate(matching_cert, compare_to):
    if (
        matching_cert.owner != compare_to.owner
        or matching_cert.san != compare_to.san
        or matching_cert.key_type != compare_to.key_type
        or matching_cert.not_before.date() != compare_to.not_before.date()
        or matching_cert.not_after.date() != compare_to.not_after.date()
        or matching_cert.authority_id != compare_to.authority_id
    ):
        return False

    matching_destinations = [destination.label for destination in matching_cert.destinations]
    compare_to_destinations = [destination.label for destination in compare_to.destinations]

    if (len(matching_destinations) == len(compare_to_destinations)
            and set(matching_destinations) == set(compare_to_destinations)):
        matching_sans = [domain.name for domain in matching_cert.domains]
        compare_to_sans = [domain.name for domain in compare_to.domains]

        return len(matching_sans) == len(compare_to_sans) and set(matching_sans) == set(compare_to_sans)

    return False


@cli.command("identify_expiring_deployed_certificates")
@click.option(
    "-e",
    "--exclude",
    "exclude_domains",
    multiple=True,
    default=[],
    help="Domains that should be excluded from check.",
)
@click.option(
    "-eo",
    "--exclude-owners",
    "exclude_owners",
    multiple=True,
    default=[],
    help="Owners that should be excluded from check.",
)
@click.option(
    "-c",
    "--commit",
    "commit",
    default=False,
    help="Persist changes.",
)
def identify_expiring_deployed_certificates_command(exclude_domains, exclude_owners, commit):
    identify_expiring_deployed_certificates(exclude_domains, exclude_owners, commit)


def identify_expiring_deployed_certificates(exclude_domains, exclude_owners, commit):
    status = FAILURE_METRIC_STATUS
    try:
        identify_and_persist_expiring_deployed_certificates(exclude_domains, exclude_owners, commit)
        status = SUCCESS_METRIC_STATUS
    except Exception:
        capture_exception()
        current_app.logger.exception("Error identifying expiring deployed certificates", exc_info=True)

    metrics.send("identify_expiring_deployed_certificates", "counter", 1, metric_tags={"status": status})


@cli.command("expiration_metrics")
def expiration_metrics_command(expiry_window):
    expiration_metrics(expiry_window)


def expiration_metrics(expiry_window):
    """
    Iterates over all certificates and emits a metric for the days remaining for a certificate to expire.
    This is used for building custom dashboards and alerts for certificate expiry.
    """
    try:
        click.echo("Starting to publish metrics for time left until cert expirations")
        success, failure = send_certificate_expiration_metrics(expiry_window)
        click.echo(
            f"Finished publishing metrics for time left until cert expirations! Sent: {success}"
        )
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        status = FAILURE_METRIC_STATUS
        capture_exception()

    metrics.send(
        "expiration_metrics_job", "counter", 1, metric_tags={"status": status}
    )
