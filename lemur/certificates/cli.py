"""
.. module: lemur.certificate.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
from flask import current_app
from flask_principal import Identity, identity_changed
from flask_script import Manager
from sqlalchemy import or_
from tabulate import tabulate

from lemur import database
from lemur.authorities.models import Authority
from lemur.authorities.service import get as authorities_get_by_id
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
    revoke as revoke_certificate,
)
from lemur.certificates.verify import verify_string
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS, CRLReason
from lemur.deployment import service as deployment_service
from lemur.domains.models import Domain
from lemur.endpoints import service as endpoint_service
from lemur.extensions import sentry, metrics
from lemur.notifications.messaging import send_rotation_notification
from lemur.plugins.base import plugins

manager = Manager(usage="Handles all certificate related tasks.")


def print_certificate_details(details):
    """
    Print the certificate details with formatting.
    :param details:
    :return:
    """
    details, errors = CertificateOutputSchema().dump(details)
    print("[+] Re-issuing certificate with the following details: ")
    print(
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
            print("[-] No certificate found with name: {0}".format(certificate_name))
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
            print("[-] No endpoint found with name: {0}".format(endpoint_name))
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
            print(
                "[!] Failed to rotate endpoint {0} to certificate {1} reason: {2}".format(
                    endpoint.name, certificate.name, e
                )
            )

    metrics.send("endpoint_rotation", "counter", 1, metric_tags={"status": status})


def request_reissue(certificate, commit):
    """
    Reissuing certificate and handles any exceptions.
    :param certificate:
    :param commit:
    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("[+] {0} is eligible for re-issuance".format(certificate.name))

        # set the lemur identity for all cli commands
        identity_changed.send(current_app._get_current_object(), identity=Identity(1))

        details = get_certificate_primitives(certificate)
        print_certificate_details(details)

        if commit:
            new_cert = reissue_certificate(certificate, replace=True)
            print("[+] New certificate named: {0}".format(new_cert.name))

        status = SUCCESS_METRIC_STATUS

    except Exception as e:
        sentry.captureException(extra={"certificate_name": str(certificate.name)})
        current_app.logger.exception(
            f"Error reissuing certificate: {certificate.name}", exc_info=True
        )
        print(f"[!] Failed to reissue certificate: {certificate.name}. Reason: {e}")

    metrics.send(
        "certificate_reissue",
        "counter",
        1,
        metric_tags={"status": status, "certificate": certificate.name},
    )


@manager.option(
    "-e",
    "--endpoint",
    dest="endpoint_name",
    help="Name of the endpoint you wish to rotate.",
)
@manager.option(
    "-n",
    "--new-certificate",
    dest="new_certificate_name",
    help="Name of the certificate you wish to rotate to.",
)
@manager.option(
    "-o",
    "--old-certificate",
    dest="old_certificate_name",
    help="Name of the certificate you wish to rotate.",
)
@manager.option(
    "-a",
    "--notify",
    dest="message",
    action="store_true",
    help="Send a rotation notification to the certificates owner.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def rotate(endpoint_name, new_certificate_name, old_certificate_name, message, commit):
    """
    Rotates an endpoint and reissues it if it has not already been replaced. If it has
    been replaced, will use the replacement certificate for the rotation.
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting endpoint rotation.")

    status = FAILURE_METRIC_STATUS

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
    }

    try:
        old_cert = validate_certificate(old_certificate_name)
        new_cert = validate_certificate(new_certificate_name)
        endpoint = validate_endpoint(endpoint_name)

        if endpoint and new_cert:
            print(
                f"[+] Rotating endpoint: {endpoint.name} to certificate {new_cert.name}"
            )
            log_data["message"] = "Rotating endpoint"
            log_data["endpoint"] = endpoint.dnsname
            log_data["certificate"] = new_cert.name
            request_rotation(endpoint, new_cert, message, commit)
            current_app.logger.info(log_data)

        elif old_cert and new_cert:
            print(f"[+] Rotating all endpoints from {old_cert.name} to {new_cert.name}")

            log_data["message"] = "Rotating all endpoints"
            log_data["certificate"] = new_cert.name
            log_data["certificate_old"] = old_cert.name
            log_data["message"] = "Rotating endpoint from old to new cert"
            for endpoint in old_cert.endpoints:
                print(f"[+] Rotating {endpoint.name}")
                log_data["endpoint"] = endpoint.dnsname
                request_rotation(endpoint, new_cert, message, commit)
                current_app.logger.info(log_data)

        else:
            print("[+] Rotating all endpoints that have new certificates available")
            log_data["message"] = "Rotating all endpoints that have new certificates available"
            for endpoint in endpoint_service.get_all_pending_rotation():
                log_data["endpoint"] = endpoint.dnsname
                if len(endpoint.certificate.replaced) == 1:
                    print(
                        f"[+] Rotating {endpoint.name} to {endpoint.certificate.replaced[0].name}"
                    )
                    log_data["certificate"] = endpoint.certificate.replaced[0].name
                    request_rotation(
                        endpoint, endpoint.certificate.replaced[0], message, commit
                    )
                    current_app.logger.info(log_data)

                else:
                    log_data["message"] = "Failed to rotate endpoint due to Multiple replacement certificates found"
                    print(log_data)
                    metrics.send(
                        "endpoint_rotation",
                        "counter",
                        1,
                        metric_tags={
                            "status": FAILURE_METRIC_STATUS,
                            "old_certificate_name": str(old_cert),
                            "new_certificate_name": str(
                                endpoint.certificate.replaced[0].name
                            ),
                            "endpoint_name": str(endpoint.name),
                            "message": str(message),
                        },
                    )
                    print(
                        f"[!] Failed to rotate endpoint {endpoint.name} reason: "
                        "Multiple replacement certificates found."
                    )

        status = SUCCESS_METRIC_STATUS
        print("[+] Done!")

    except Exception as e:
        sentry.captureException(
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

    print(log_data)
    current_app.logger.info(log_data)


@manager.option(
    "-e",
    "--endpoint",
    dest="endpoint_name",
    help="Name of the endpoint you wish to rotate.",
)
@manager.option(
    "-n",
    "--new-certificate",
    dest="new_certificate_name",
    help="Name of the certificate you wish to rotate to.",
)
@manager.option(
    "-o",
    "--old-certificate",
    dest="old_certificate_name",
    help="Name of the certificate you wish to rotate.",
)
@manager.option(
    "-a",
    "--notify",
    dest="message",
    action="store_true",
    help="Send a rotation notification to the certificates owner.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
@manager.option(
    "-r",
    "--region",
    dest="region",
    required=True,
    help="Region in which to rotate the endpoint.",
)
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
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting endpoint rotation.")
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
            print(log_data)
            current_app.logger.info(log_data)
            for endpoint in old_cert.endpoints:
                log_data["endpoint"] = endpoint.dnsname
                request_rotation_region(endpoint, new_cert, message, commit, log_data, region)

        else:
            log_data["message"] = "Rotating all endpoints that have new certificates available"
            print(log_data)
            current_app.logger.info(log_data)
            all_pending_rotation_endpoints = endpoint_service.get_all_pending_rotation()
            for endpoint in all_pending_rotation_endpoints:
                log_data["endpoint"] = endpoint.dnsname
                if region not in endpoint.dnsname:
                    log_data["message"] = "Skipping rotation, region mismatch"
                    print(log_data)
                    current_app.logger.info(log_data)
                    metrics.send(
                        "endpoint_rotation_region_skipped",
                        "counter",
                        1,
                        metric_tags={
                            "region": region,
                            "old_certificate_name": str(old_cert),
                            "new_certificate_name": str(endpoint.certificate.replaced[0].name),
                            "endpoint_name": str(endpoint.dnsname),
                        },
                    )

                if len(endpoint.certificate.replaced) == 1:
                    log_data["certificate"] = endpoint.certificate.replaced[0].name
                    log_data["message"] = "Rotating all endpoints in region"
                    print(log_data)
                    current_app.logger.info(log_data)
                    request_rotation(endpoint, endpoint.certificate.replaced[0], message, commit)
                    status = SUCCESS_METRIC_STATUS
                else:
                    status = FAILURE_METRIC_STATUS
                    log_data["message"] = "Failed to rotate endpoint due to Multiple replacement certificates found"
                    print(log_data)
                    current_app.logger.info(log_data)

                metrics.send(
                    "endpoint_rotation_region",
                    "counter",
                    1,
                    metric_tags={
                        "status": FAILURE_METRIC_STATUS,
                        "old_certificate_name": str(old_cert),
                        "new_certificate_name": str(endpoint.certificate.replaced[0].name),
                        "endpoint_name": str(endpoint.dnsname),
                        "message": str(message),
                        "region": str(region),
                    },
                )
        status = SUCCESS_METRIC_STATUS
        print("[+] Done!")

    except Exception as e:
        sentry.captureException(
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


@manager.option(
    "-o",
    "--old-certificate",
    dest="old_certificate_name",
    help="Name of the certificate you wish to reissue.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def reissue(old_certificate_name, commit):
    """
    Reissues certificate with the same parameters as it was originally issued with.
    If not time period is provided, reissues certificate as valid from today to
    today + length of original.
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting certificate re-issuance.")

    status = FAILURE_METRIC_STATUS

    try:
        old_cert = validate_certificate(old_certificate_name)

        if not old_cert:
            for certificate in get_all_pending_reissue():
                request_reissue(certificate, commit)
        else:
            request_reissue(old_cert, commit)

        status = SUCCESS_METRIC_STATUS
        print("[+] Done!")
    except Exception as e:
        sentry.captureException()
        current_app.logger.exception("Error reissuing certificate.", exc_info=True)
        print("[!] Failed to reissue certificates. Reason: {}".format(e))

    metrics.send(
        "certificate_reissue_job", "counter", 1, metric_tags={"status": status}
    )


@manager.option(
    "-f",
    "--fqdns",
    dest="fqdns",
    help="FQDNs to query. Multiple fqdns specified via comma.",
)
@manager.option("-i", "--issuer", dest="issuer", help="Issuer to query for.")
@manager.option("-o", "--owner", dest="owner", help="Owner to query for.")
@manager.option(
    "-e",
    "--expired",
    dest="expired",
    type=bool,
    default=False,
    help="Include expired certificates.",
)
def query(fqdns, issuer, owner, expired):
    """Prints certificates that match the query params."""
    table = []

    q = database.session_query(Certificate)
    if issuer:
        sub_query = (
            database.session_query(Authority.id)
            .filter(Authority.name.ilike("%{0}%".format(issuer)))
            .subquery()
        )

        q = q.filter(
            or_(
                Certificate.issuer.ilike("%{0}%".format(issuer)),
                Certificate.authority_id.in_(sub_query),
            )
        )
    if owner:
        q = q.filter(Certificate.owner.ilike("%{0}%".format(owner)))

    if not expired:
        q = q.filter(Certificate.expired == False)  # noqa

    if fqdns:
        for f in fqdns.split(","):
            q = q.filter(
                or_(
                    Certificate.cn.ilike("%{0}%".format(f)),
                    Certificate.domains.any(Domain.name.ilike("%{0}%".format(f))),
                )
            )

    for c in q.all():
        table.append([c.id, c.name, c.owner, c.issuer])

    print(tabulate(table, headers=["Id", "Name", "Owner", "Issuer"], tablefmt="csv"))


def worker(data, commit, reason):
    parts = [x for x in data.split(" ") if x]
    try:
        cert = get(int(parts[0].strip()))

        print("[+] Revoking certificate. Id: {0} Name: {1}".format(cert.id, cert.name))
        if commit:
            revoke_certificate(cert, reason)

        metrics.send(
            "certificate_revoke",
            "counter",
            1,
            metric_tags={"status": SUCCESS_METRIC_STATUS},
        )

    except Exception as e:
        sentry.captureException()
        metrics.send(
            "certificate_revoke",
            "counter",
            1,
            metric_tags={"status": FAILURE_METRIC_STATUS},
        )
        print("[!] Failed to revoke certificates. Reason: {}".format(e))


@manager.command
def clear_pending():
    """
    Function clears all pending certificates.
    :return:
    """
    v = plugins.get("verisign-issuer")
    v.clear_pending_certificates()


@manager.option("-p", "--path", dest="path", help="Absolute file path to a Lemur query csv.")
@manager.option("-id", "--certid", dest="cert_id", help="ID of the certificate to be revoked")
@manager.option("-r", "--reason", dest="reason", default="unspecified", help="CRL Reason as per RFC 5280 section 5.3.1")
@manager.option("-m", "--message", dest="message", help="Message explaining reason for revocation")
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def revoke(path, cert_id, reason, message, commit):
    """
    Revokes given certificate.
    """
    if not path and not cert_id:
        print("[!] No input certificates mentioned to revoke")
        return
    if path and cert_id:
        print("[!] Please mention single certificate id (-id) or input file (-p)")
        return

    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting certificate revocation.")

    if reason not in CRLReason.__members__:
        reason = CRLReason.unspecified.name
    comments = {"comments": message, "crl_reason": reason}

    if cert_id:
        worker(cert_id, commit, comments)
    else:
        with open(path, "r") as f:
            for x in f.readlines()[2:]:
                worker(x, commit, comments)


@manager.command
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

    certs = get_all_valid_certs(current_app.config.get("SUPPORTED_REVOCATION_AUTHORITY_PLUGINS", []))
    for cert in certs:
        try:
            if cert.chain:
                status = verify_string(cert.body, cert.chain)
            else:
                status = verify_string(cert.body, "")

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
            sentry.captureException()
            current_app.logger.exception(e)
            cert.status = "unknown"

        database.update(cert)


@manager.command
def automatically_enable_autorotate():
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
        metrics.send("automatically_enable_autorotate",
                     "counter", 1,
                     metric_tags={"certificate": log_data["certificate"],
                                  "certificate_id": log_data["certificate_id"],
                                  "authority_id": log_data["authority_id"],
                                  "authority_name": log_data["authority_name"],
                                  "destination_names": log_data["destination_names"]
                                  })
        cert.rotation = True
        database.update(cert)


@manager.command
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
    for cert in certificates:
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
            sentry.captureException()
            current_app.logger.exception(e)
