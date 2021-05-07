"""
.. module: lemur.certificates.verify
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import requests
import subprocess
from flask import current_app
from requests.exceptions import ConnectionError, InvalidSchema
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sentry_sdk import capture_exception

from lemur.utils import mktempfile
from lemur.common.utils import parse_certificate

crl_cache = {}


def ocsp_verify(cert, cert_path, issuer_chain_path):
    """
    Attempts to verify a certificate via OCSP. OCSP is a more modern version
    of CRL in that it will query the OCSP URI in order to determine if the
    certificate has been revoked

    :param cert:
    :param cert_path:
    :param issuer_chain_path:
    :return bool: True if certificate is valid, False otherwise
    """
    command = ["openssl", "x509", "-noout", "-ocsp_uri", "-in", cert_path]
    p1 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url, err = p1.communicate()

    if not url:
        current_app.logger.debug(
            "No OCSP URL in certificate {}".format(cert.serial_number)
        )
        return None

    p2 = subprocess.Popen(
        [
            "openssl",
            "ocsp",
            "-issuer",
            issuer_chain_path,
            "-cert",
            cert_path,
            "-url",
            url.strip(),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    message, err = p2.communicate()

    p_message = message.decode("utf-8")

    if "error" in p_message or "Error" in p_message:
        raise Exception("Got error when parsing OCSP url")

    elif "revoked" in p_message:
        current_app.logger.debug(
            "OCSP reports certificate revoked: {}".format(cert.serial_number)
        )
        return False

    elif "good" not in p_message:
        raise Exception("Did not receive a valid response")

    return True


def crl_verify(cert, cert_path):
    """
    Attempts to verify a certificate using CRL.

    :param cert:
    :param cert_path:
    :return: True if certificate is valid, False otherwise
    :raise Exception: If certificate does not have CRL
    """
    try:
        distribution_points = cert.extensions.get_extension_for_oid(
            x509.OID_CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        current_app.logger.debug(
            "No CRLDP extension in certificate {}".format(cert.serial_number)
        )
        return None

    for p in distribution_points:
        point = p.full_name[0].value

        if point not in crl_cache:
            current_app.logger.debug("Retrieving CRL: {}".format(point))
            try:
                response = requests.get(point)

                if response.status_code != 200:
                    raise Exception("Unable to retrieve CRL: {0}".format(point))
            except InvalidSchema:
                # Unhandled URI scheme (like ldap://); skip this distribution point.
                continue
            except ConnectionError:
                raise Exception("Unable to retrieve CRL: {0}".format(point))

            crl_cache[point] = x509.load_der_x509_crl(
                response.content, backend=default_backend()
            )
        else:
            current_app.logger.debug("CRL point is cached {}".format(point))

        for r in crl_cache[point]:
            if cert.serial_number == r.serial_number:
                try:
                    reason = r.extensions.get_extension_for_class(x509.CRLReason).value
                    # Handle "removeFromCRL" revoke reason as unrevoked;
                    # continue with the next distribution point.
                    # Per RFC 5280 section 6.3.3 (k):
                    #  https://tools.ietf.org/html/rfc5280#section-6.3.3
                    if reason == x509.ReasonFlags.remove_from_crl:
                        break
                except x509.ExtensionNotFound:
                    pass

                current_app.logger.debug(
                    "CRL reports certificate " "revoked: {}".format(cert.serial_number)
                )
                return False

    return True


def verify(cert_path, issuer_chain_path):
    """
    Verify a certificate using OCSP and CRL

    :param cert_path:
    :param issuer_chain_path:
    :return: True if valid, False otherwise
    """
    with open(cert_path, "rt") as c:
        try:
            cert = parse_certificate(c.read())
        except ValueError as e:
            current_app.logger.error(e)
            return None

    # OCSP is our main source of truth, in a lot of cases CRLs
    # have been deprecated and are no longer updated
    verify_result = None
    try:
        verify_result = ocsp_verify(cert, cert_path, issuer_chain_path)
    except Exception as e:
        capture_exception()
        current_app.logger.exception(e)

    if verify_result is None:
        try:
            verify_result = crl_verify(cert, cert_path)
        except Exception as e:
            capture_exception()
            current_app.logger.exception(e)

    if verify_result is None:
        current_app.logger.debug("Failed to verify {}".format(cert.serial_number))

    return verify_result


def verify_string(cert_string, issuer_string):
    """
    Verify a certificate given only it's string value

    :param cert_string:
    :param issuer_string:
    :return: True if valid, False otherwise
    """
    with mktempfile() as cert_tmp:
        with open(cert_tmp, "w") as f:
            f.write(cert_string)
        with mktempfile() as issuer_tmp:
            with open(issuer_tmp, "w") as f:
                f.write(issuer_string)
            status = verify(cert_tmp, issuer_tmp)
    return status
