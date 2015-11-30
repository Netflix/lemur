"""
.. module: lemur.certificates.verify
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import requests
import subprocess
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from flask import current_app
from lemur.utils import mktempfile


def ocsp_verify(cert_path, issuer_chain_path):
    """
    Attempts to verify a certificate via OCSP. OCSP is a more modern version
    of CRL in that it will query the OCSP URI in order to determine if the
    certificate as been revoked

    :param cert_path:
    :param issuer_chain_path:
    :return bool: True if certificate is valid, False otherwise
    """
    command = ['openssl', 'x509', '-noout', '-ocsp_uri', '-in', cert_path]
    p1 = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url, err = p1.communicate()

    p2 = subprocess.Popen(['openssl', 'ocsp', '-issuer', issuer_chain_path,
                           '-cert', cert_path, "-url", url.strip()], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    message, err = p2.communicate()
    if 'error' in message or 'Error' in message:
        raise Exception("Got error when parsing OCSP url")

    elif 'revoked' in message:
        return

    elif 'good' not in message:
        raise Exception("Did not receive a valid response")

    return True


def crl_verify(cert_path):
    """
    Attempts to verify a certificate using CRL.

    :param cert_path:
    :return: True if certificate is valid, False otherwise
    :raise Exception: If certificate does not have CRL
    """
    with open(cert_path, 'rt') as c:
        cert = x509.load_pem_x509_certificate(c.read(), default_backend())

    distribution_points = cert.extensions.get_extension_for_oid(x509.OID_CRL_DISTRIBUTION_POINTS).value
    for p in distribution_points:
        point = p.full_name[0].value
        response = requests.get(point)
        crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)  # TODO this should be switched to cryptography when support exists
        revoked = crl.get_revoked()
        for r in revoked:
            if cert.serial == r.get_serial():
                return
    return True


def verify(cert_path, issuer_chain_path):
    """
    Verify a certificate using OCSP and CRL

    :param cert_path:
    :param issuer_chain_path:
    :return: True if valid, False otherwise
    """
    # OCSP is our main source of truth, in a lot of cases CRLs
    # have been deprecated and are no longer updated
    try:
        return ocsp_verify(cert_path, issuer_chain_path)
    except Exception as e:
        current_app.logger.debug("Could not use OCSP: {0}".format(e))
        try:
            return crl_verify(cert_path)
        except Exception as e:
            current_app.logger.debug("Could not use CRL: {0}".format(e))
            raise Exception("Failed to verify")
        raise Exception("Failed to verify")


def verify_string(cert_string, issuer_string):
    """
    Verify a certificate given only it's string value

    :param cert_string:
    :param issuer_string:
    :return: True if valid, False otherwise
    """
    with mktempfile() as cert_tmp:
        with open(cert_tmp, 'w') as f:
            f.write(cert_string)
        with mktempfile() as issuer_tmp:
            with open(issuer_tmp, 'w') as f:
                f.write(issuer_string)
            status = verify(cert_tmp, issuer_tmp)
    return status
