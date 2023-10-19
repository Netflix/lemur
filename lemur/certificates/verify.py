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
from requests.exceptions import ConnectionError, InvalidSchema, Timeout
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sentry_sdk import capture_exception
from subprocess import TimeoutExpired

from lemur.utils import mktempfile
from lemur.common.utils import parse_certificate
from lemur.extensions import metrics

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
            f"No OCSP URL in certificate {cert.serial_number}"
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
    if not isinstance(url, str):
        url = url.decode("utf-8")
    try:
        message, err = p2.communicate(timeout=6)
    except TimeoutExpired:
        try:
            p2.kill()
        except OSError:
            # Ignore 'no such process' error
            pass
        raise Exception(f"OCSP lookup timed out: {url}, certificate serial number {cert.serial_number:02X}")

    p_message = message.decode("utf-8")

    if "unauthorized" in p_message:
        # indicates the OCSP server does not know this certificate. this is a retriable error.
        metrics.send("check_revocation_ocsp_verify", "counter", 1, metric_tags={"status": "unauthorized", "url": url})
        current_app.logger.warning(f"OCSP unauthorized error: {url}, "
                                   f"certificate serial number {cert.serial_number:02X}. Response: {p_message}")
        return None

    elif "error" in p_message or "Error" in p_message:
        metrics.send("check_revocation_ocsp_verify", "counter", 1, metric_tags={"status": "error", "url": url})
        raise Exception(f"Got error when parsing response from OCSP url: {url}, certificate serial number "
                        f"{cert.serial_number:02X}. Response: {p_message}")

    elif "revoked" in p_message:
        current_app.logger.debug(
            f"OCSP reports certificate revoked, serial number: {cert.serial_number:02X}"
        )
        return False

    elif "good" not in p_message:
        raise Exception(f"Did not receive a valid OCSP response from url: {url}, "
                        f"certificate serial number {cert.serial_number:02X}")

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
            f"No CRLDP extension in certificate {cert.serial_number}"
        )
        return None

    for p in distribution_points:
        point = p.full_name[0].value

        if point not in crl_cache:
            current_app.logger.debug(f"Retrieving CRL: {point}, serial {cert.serial_number:02X}")
            try:
                response = requests.get(point, timeout=(3.05, 6))

                if response.status_code != 200:
                    raise Exception(f"Unable to retrieve CRL: {point}, serial {cert.serial_number:02X}")
            except InvalidSchema:
                # Unhandled URI scheme (like ldap://); skip this distribution point.
                continue
            except (ConnectionError, Timeout):
                raise Exception(f"Unable to retrieve CRL: {point}, serial {cert.serial_number:02X}")

            crl_cache[point] = x509.load_der_x509_crl(
                response.content, backend=default_backend()
            )
        else:
            current_app.logger.debug(f"CRL point is cached {point}")

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
    with open(cert_path) as c:
        try:
            cert = parse_certificate(c.read())
        except ValueError as e:
            current_app.logger.error(e)
            return None

    # OCSP is our main source of truth, in a lot of cases CRLs
    # have been deprecated and are no longer updated
    verify_result = None
    ocsp_err = 0
    crl_err = 0
    try:
        verify_result = ocsp_verify(cert, cert_path, issuer_chain_path)
    except Exception as e:
        capture_exception()
        current_app.logger.warning(e)
        ocsp_err = 1

    if verify_result is None:
        try:
            verify_result = crl_verify(cert, cert_path)
        except Exception as e:
            capture_exception()
            current_app.logger.warning(e)
            crl_err = 1

    if verify_result is None:
        current_app.logger.warning(f"Failed to verify {cert.serial_number}")

    return verify_result, ocsp_err, crl_err


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
            status, ocsp_err, crl_err = verify(cert_tmp, issuer_tmp)
    return status, ocsp_err, crl_err
