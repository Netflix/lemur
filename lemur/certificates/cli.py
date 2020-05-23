"""
.. module: lemur.certificate.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
import multiprocessing
from tabulate import tabulate
from sqlalchemy import or_

from flask import current_app

from flask_script import Manager
from flask_principal import Identity, identity_changed


from lemur import database
from lemur.extensions import sentry
from lemur.extensions import metrics
from lemur.plugins.base import plugins
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.deployment import service as deployment_service
from lemur.endpoints import service as endpoint_service
from lemur.notifications.messaging import send_rotation_notification
from lemur.domains.models import Domain
from lemur.authorities.models import Authority
from lemur.certificates.schemas import CertificateOutputSchema
from lemur.certificates.models import Certificate
from lemur.certificates.service import (
    reissue_certificate,
    get_certificate_primitives,
    get_all_pending_reissue,
    get_by_name,
    get_all_valid_certs,
    get,
)

from lemur.certificates.verify import verify_string

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

    try:
        old_cert = validate_certificate(old_certificate_name)
        new_cert = validate_certificate(new_certificate_name)
        endpoint = validate_endpoint(endpoint_name)

        if endpoint and new_cert:
            print(
                f"[+] Rotating endpoint: {endpoint.name} to certificate {new_cert.name}"
            )
            request_rotation(endpoint, new_cert, message, commit)

        elif old_cert and new_cert:
            print(f"[+] Rotating all endpoints from {old_cert.name} to {new_cert.name}")

            for endpoint in old_cert.endpoints:
                print(f"[+] Rotating {endpoint.name}")
                request_rotation(endpoint, new_cert, message, commit)

        else:
            print("[+] Rotating all endpoints that have new certificates available")
            for endpoint in endpoint_service.get_all_pending_rotation():
                if len(endpoint.certificate.replaced) == 1:
                    print(
                        f"[+] Rotating {endpoint.name} to {endpoint.certificate.replaced[0].name}"
                    )
                    request_rotation(
                        endpoint, endpoint.certificate.replaced[0], message, commit
                    )
                else:
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
        plugin = plugins.get(cert.authority.plugin_name)

        print("[+] Revoking certificate. Id: {0} Name: {1}".format(cert.id, cert.name))
        if commit:
            plugin.revoke_certificate(cert, reason)

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


@manager.option(
    "-p", "--path", dest="path", help="Absolute file path to a Lemur query csv."
)
@manager.option("-r", "--reason", dest="reason", help="Reason to revoke certificate.")
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def revoke(path, reason, commit):
    """
    Revokes given certificate.
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting certificate revocation.")

    with open(path, "r") as f:
        args = [[x, commit, reason] for x in f.readlines()[2:]]

    with multiprocessing.Pool(processes=3) as pool:
        pool.starmap(worker, args)


@manager.command
def check_revoked():
    """
    Function attempts to update Lemur's internal cache with revoked
    certificates. This is called periodically by Lemur. It checks both
    CRLs and OCSP to see if a certificate is revoked. If Lemur is unable
    encounters an issue with verification it marks the certificate status
    as `unknown`.
    """

    certs = get_all_valid_certs(current_app.config.get("SUPPORTED_REVOCATION_AUTHORITY_PLUGINS", []))
    for cert in certs:
        try:
            if cert.chain:
                status = verify_string(cert.body, cert.chain)
            else:
                status = verify_string(cert.body, "")

            cert.status = "valid" if status else "revoked"

        except Exception as e:
            sentry.captureException()
            current_app.logger.exception(e)
            cert.status = "unknown"

        database.update(cert)
