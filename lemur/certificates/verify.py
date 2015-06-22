"""
.. module: lemur.certificates.verify
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import os
import re
import hashlib
import requests
import subprocess
from OpenSSL import crypto

from flask import current_app


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
    s = "(http(s)?\://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}/\S*?$)"
    regex = re.compile(s, re.MULTILINE)

    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_path, 'rt').read())
    for x in range(x509.get_extension_count()):
        ext = x509.get_extension(x)
        if ext.get_short_name() == 'crlDistributionPoints':
            r = regex.search(ext.get_data())
            points = r.groups()
            break
    else:
        raise Exception("Certificate does not have a CRL distribution point")

    for point in points:
        if point:
            response = requests.get(point)
            crl = crypto.load_crl(crypto.FILETYPE_ASN1, response.content)
            revoked = crl.get_revoked()
            for r in revoked:
                if x509.get_serial_number() == r.get_serial():
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


def make_tmp_file(string):
    """
    Creates a temporary file for a given string

    :param string:
    :return: Full file path to created file
    """
    m = hashlib.md5()
    m.update(string)
    hexdigest = m.hexdigest()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), hexdigest)
    with open(path, 'w') as f:
        f.write(string)
    return path


def verify_string(cert_string, issuer_string):
    """
    Verify a certificate given only it's string value

    :param cert_string:
    :param issuer_string:
    :return: True if valid, False otherwise
    """
    cert_path = make_tmp_file(cert_string)
    issuer_path = make_tmp_file(issuer_string)
    status = verify(cert_path, issuer_path)
    remove_tmp_file(cert_path)
    remove_tmp_file(issuer_path)
    return status


def remove_tmp_file(file_path):
    os.remove(file_path)