"""
.. module: lemur.certificate.cli
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys

from flask import current_app

from flask_script import Manager

from lemur import database
from lemur.extensions import metrics
from lemur.deployment import service as deployment_service
from lemur.endpoints import service as endpoint_service
from lemur.notifications.messaging import send_rotation_notification
from lemur.certificates.service import reissue_certificate, get_certificate_primitives, get_all_pending_reissue, get_by_name, get_all_certs

from lemur.certificates.verify import verify_string

manager = Manager(usage="Handles all certificate related tasks.")


def print_certificate_details(details):
    """
    Print the certificate details with formatting.
    :param details:
    :return:
    """
    print("[+] Re-issuing certificate with the following details: ")
    print(
        "\t[+] Common Name: {common_name}\n"
        "\t[+] Subject Alternate Names: {sans}\n"
        "\t[+] Authority: {authority_name}\n"
        "\t[+] Validity Start: {validity_start}\n"
        "\t[+] Validity End: {validity_end}\n"
        "\t[+] Organization: {organization}\n"
        "\t[+] Organizational Unit: {organizational_unit}\n"
        "\t[+] Country: {country}\n"
        "\t[+] State: {state}\n"
        "\t[+] Location: {location}".format(
            common_name=details['common_name'],
            sans=",".join(x['value'] for x in details['extensions']['sub_alt_names']['names']) or None,
            authority_name=details['authority'].name,
            validity_start=details['validity_start'].isoformat(),
            validity_end=details['validity_end'].isoformat(),
            organization=details['organization'],
            organizational_unit=details['organizational_unit'],
            country=details['country'],
            state=details['state'],
            location=details['location']
        )
    )


def validate_certificate(certificate_name):
    if certificate_name:
        cert = get_by_name(certificate_name)

        if not cert:
            print("[-] No certificate found with name: {0}".format(certificate_name))
            sys.exit(1)

        return cert


def validate_endpoint(endpoint_name):
    if endpoint_name:
        endpoint = endpoint_service.get_by_name(endpoint_name)

        if not endpoint:
            print("[-] No endpoint found with name: {0}".format(endpoint_name))
            sys.exit(1)

        return endpoint


def rotate_endpoint(endpoint, certificate, message, commit):
    if commit:
        try:
            deployment_service.rotate_certificate(endpoint, certificate)
            metrics.send('endpoint_rotation_success', 'counter', 1)

            if message:
                send_rotation_notification(certificate)

        except Exception as e:
            metrics.send('endpoint_rotation_failure', 'counter', 1)
            print("[!] Failed to rotate endpoint {0} to certificate {1} reason: {3}".format(
                endpoint.name,
                certificate.name,
                e
            ))


@manager.option('-e', '--endpoint', dest='endpoint_name', help='Name of the endpoint you wish to rotate.')
@manager.option('-n', '--new-certificate', dest='new_certificate_name', help='Name of the certificate you wish to rotate to.')
@manager.option('-o', '--old-certificate', dest='old_certificate_name', help='Name of the certificate you wish to rotate.')
@manager.option('-a', '--notify', dest='message', action='store_true', help='Send a rotation notification to the certificates owner.')
@manager.option('-c', '--commit', dest='commit', action='store_true', default=False, help='Persist changes.')
def rotate(endpoint_name, new_certificate_name, old_certificate_name, message, commit):
    """
    Rotates an endpoint and reissues it if it has not already been replaced. If it has
    been replaced, will use the replacement certificate for the rotation.
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    print("[+] Starting endpoint rotation.")

    old_cert = validate_certificate(old_certificate_name)
    new_cert = validate_certificate(new_certificate_name)
    endpoint = validate_endpoint(endpoint_name)

    if endpoint and new_cert:
        print("[+] Rotating endpoint: {0} to certificate {1}".format(endpoint.name, new_cert.name))
        rotate_endpoint(endpoint, new_cert, message, commit)

    elif old_cert and new_cert:
        print("[+] Rotating all endpoints from {0} to {1}".format(old_cert.name, new_cert.name))

        for endpoint in old_cert.endpoints:
            print("[+] Rotating {0}".format(endpoint.name))
            rotate_endpoint(endpoint, new_cert, message, commit)

    else:
        print("[+] Rotating all endpoints that have new certificates available")
        for endpoint in endpoint_service.get_all_pending_rotation():
            if len(endpoint.certificate.replaced) == 1:
                print("[+] Rotating {0} to {1}".format(endpoint.name, endpoint.certificate.replaced[0].name))
                rotate_endpoint(endpoint, endpoint.certificate.replaced[0], message, commit)
            else:
                metrics.send('endpoint_rotation_failure', 'counter', 1)
                print("[!] Failed to rotate endpoint {0} reason: Multiple replacement certificates found.".format(
                    endpoint.name
                ))

    print("[+] Done!")


@manager.option('-o', '--old-certificate', dest='old_certificate_name', help='Name of the certificate you wish to reissue.')
@manager.option('-c', '--commit', dest='commit', action='store_true', default=False, help='Persist changes.')
def reissue(old_certificate_name, commit):
    """
    Reissues certificate with the same parameters as it was originally issued with.
    If not time period is provided, reissues certificate as valid from today to
    today + length of original.
    """
    if commit:
        print("[!] Running in COMMIT mode.")

    old_cert = get_by_name(old_certificate_name)

    if not old_cert:
        for certificate in get_all_pending_reissue():
            print("[+] {0} is eligible for re-issuance".format(certificate.name))
            details = get_certificate_primitives(certificate)
            print_certificate_details(details)

            if commit:
                new_cert = reissue_certificate(certificate, replace=True)
                print("[+] New certificate named: {0}".format(new_cert.name))

    else:
        details = get_certificate_primitives(old_cert)
        print_certificate_details(details)

        if commit:
            new_cert = reissue_certificate(old_cert, replace=True)
            print("[+] New certificate named: {0}".format(new_cert.name))

    print("[+] Done!")


@manager.command
def check_revoked():
    """
    Function attempts to update Lemur's internal cache with revoked
    certificates. This is called periodically by Lemur. It checks both
    CRLs and OCSP to see if a certificate is revoked. If Lemur is unable
    encounters an issue with verification it marks the certificate status
    as `unknown`.
    """
    for cert in get_all_certs():
        try:
            if cert.chain:
                status = verify_string(cert.body, cert.chain)
            else:
                status = verify_string(cert.body, "")

            cert.status = 'valid' if status else 'invalid'

        except Exception as e:
            current_app.logger.exception(e)
            cert.status = 'unknown'

        database.update(cert)
