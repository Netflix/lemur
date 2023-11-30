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
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from lemur.common.utils import get_key_type_from_ec_curve


def get_sans_from_csr(data):
    """
    Fetches SubjectAlternativeNames from CSR.
    Works with any kind of SubjectAlternativeName
    :param data: PEM-encoded string with CSR
    :return: List of LemurAPI-compatible subAltNames
    """
    sub_alt_names = []
    try:
        request = x509.load_pem_x509_csr(data.encode("utf-8"), default_backend())
    except Exception:
        raise ValidationError("CSR presented is not valid.")

    try:
        alt_names = request.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        for alt_name in alt_names.value:
            sub_alt_names.append(
                {"nameType": type(alt_name).__name__, "value": alt_name.value}
            )
    except x509.ExtensionNotFound:
        pass

    return sub_alt_names


def get_cn_from_csr(data):
    """
    Fetches common name (CN) from CSR.
    Works with any kind of SubjectAlternativeName
    :param data: PEM-encoded string with CSR
    :return: the common name
    """
    try:
        request = x509.load_pem_x509_csr(data.encode("utf-8"), default_backend())
    except Exception:
        raise ValidationError("CSR presented is not valid.")

    common_name = request.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not common_name:
        return None
    return common_name[0].value


def get_key_type_from_csr(data):
    """
    Fetches key_type from CSR.
    Works with any kind of SubjectAlternativeName
    :param data: PEM-encoded string with CSR
    :return: key_type
    """
    try:
        request = x509.load_pem_x509_csr(data.encode("utf-8"), default_backend())
    except Exception:
        raise ValidationError("CSR presented is not valid.")

    try:
        if isinstance(request.public_key(), rsa.RSAPublicKey):
            return "RSA{key_size}".format(
                key_size=request.public_key().key_size
            )
        elif isinstance(request.public_key(), ec.EllipticCurvePublicKey):
            return get_key_type_from_ec_curve(request.public_key().curve.name)
        else:
            raise Exception("Unsupported key type")

    except NotImplemented:
        raise NotImplementedError
