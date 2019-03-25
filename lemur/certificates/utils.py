"""
Utils to parse certificate data.

.. module: lemur.certificates.hooks
    :platform: Unix
    :copyright: (c) 2019 by Javier Ramos, see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Javier Ramos <javier.ramos@booking.com>
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from marshmallow.exceptions import ValidationError


def get_dns_names_from_csr(data):
    """
    Fetches DNSNames from CSR.
    Potentially extendable to any kind of SubjectAlternativeName
    :param data: PEM-encoded string with CSR
    :return:
    """
    dns_names = []
    try:
        request = x509.load_pem_x509_csr(data.encode('utf-8'), default_backend())
    except Exception:
        raise ValidationError('CSR presented is not valid.')

    try:
        alt_names = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        for name in alt_names.value.get_values_for_type(x509.DNSName):
            dns_name = {
                'nameType': 'DNSName',
                'value': name
            }
            dns_names.append(dns_name)
    except x509.ExtensionNotFound:
        pass

    return dns_names
