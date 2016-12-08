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
from lemur.deployment.service import rotate_certificate
from lemur.notifications.messaging import send_rotation_notification
from lemur.certificates.service import reissue_certificate, get_certificate_primitives, get_all_pending_rotation, get_by_name, get_all_certs

from lemur.certificates.verify import verify_string

manager = Manager(usage="Handles all certificate related tasks.")


def reissue_and_rotate(old_certificate, new_certificate=None, commit=False, message=False):
    if not new_certificate:
        # we don't want to re-issue if it's already been replaced
        if not old_certificate.replaced:
            details = get_certificate_primitives(old_certificate)
            print_certificate_details(details)

            if commit:
                new_certificate = reissue_certificate(old_certificate, replace=True)
                print("[+] Issued new certificate named: {0}".format(new_certificate.name))

            print("[+] Done!")

        else:
            new_certificate = old_certificate.replaced
            print("[!] Certificate has been replaced by: {0}".format(old_certificate.replaced.name))

    if len(old_certificate.endpoints) > 0:
        for endpoint in old_certificate.endpoints:
            print(
                "[+] Certificate deployed on endpoint: name:{name} dnsname:{dnsname} port:{port} type:{type}".format(
                    name=endpoint.name,
                    dnsname=endpoint.dnsname,
                    port=endpoint.port,
                    type=endpoint.type
                )
            )
            print("[+] Rotating certificate from: {0} to: {1}".format(old_certificate.name, new_certificate.name))

            if commit:
                rotate_certificate(endpoint, new_certificate)

            print("[+] Done!")

    if message:
        send_rotation_notification(old_certificate)


def print_certificate_details(details):
    """
    Print the certificate details with formatting.
    :param details:
    :return:
    """
    print("[+] Re-issuing certificate with the following details: ")
    print(
        "[+] Common Name: {common_name}\n"
        "[+] Subject Alternate Names: {sans}\n"
        "[+] Authority: {authority_name}\n"
        "[+] Validity Start: {validity_start}\n"
        "[+] Validity End: {validity_end}\n"
        "[+] Organization: {organization}\n"
        "[+] Organizational Unit: {organizational_unit}\n"
        "[+] Country: {country}\n"
        "[+] State: {state}\n"
        "[+] Location: {location}\n".format(
            common_name=details['common_name'],
            sans=",".join(x['value'] for x in details['extensions']['sub_alt_names']['names']),
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


@manager.command
def rotate(new_certificate_name=False, old_certificate_name=False, message=False, commit=False):
    new_cert = old_cert = None

    if commit:
        print("[!] Running in COMMIT mode.")

    if old_certificate_name:
        old_cert = get_by_name(old_certificate_name)

        if not old_cert:
            print("[-] No certificate found with name: {0}".format(old_certificate_name))
            sys.exit(1)

    if new_certificate_name:
        new_cert = get_by_name(new_certificate_name)

        if not new_cert:
            print("[-] No certificate found with name: {0}".format(old_certificate_name))
            sys.exit(1)

    if old_cert and new_cert:
        reissue_and_rotate(old_cert, new_certificate=new_cert, commit=commit, message=message)
    else:
        for certificate in get_all_pending_rotation():
            reissue_and_rotate(certificate, commit=commit, message=message)


@manager.command
def reissue(old_certificate_name, commit=False):
    old_cert = get_by_name(old_certificate_name)

    if not old_cert:
        print("[-] No certificate found with name: {0}".format(old_certificate_name))
        sys.exit(1)

    if commit:
        print("[!] Running in COMMIT mode.")

    details = get_certificate_primitives(old_cert)
    print_certificate_details(details)

    if commit:
        new_cert = reissue_certificate(old_cert, replace=True)
        print("[+] Issued new certificate named: {0}".format(new_cert.name))

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
