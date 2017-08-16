import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import NameOID
from flask import current_app
from marshmallow.exceptions import ValidationError

from lemur.auth.permissions import SensitiveDomainPermission
from lemur.common.utils import parse_certificate, is_weekend
from lemur.domains import service as domain_service


def public_certificate(body):
    """
    Determines if specified string is valid public certificate.

    :param body:
    :return:
    """
    try:
        parse_certificate(body)
    except Exception as e:
        current_app.logger.exception(e)
        raise ValidationError('Public certificate presented is not valid.')


def private_key(key):
    """
    User to validate that a given string is a RSA private key

    :param key:
    :return: :raise ValueError:
    """
    try:
        if isinstance(key, bytes):
            serialization.load_pem_private_key(key, None, backend=default_backend())
        else:
            serialization.load_pem_private_key(key.encode('utf-8'), None, backend=default_backend())
    except Exception:
        raise ValidationError('Private key presented is not valid.')


def common_name(value):
    """If the common name could be a domain name, apply domain validation rules."""
    # Common name could be a domain name, or a human-readable name of the subject (often used in CA names or client
    # certificates). As a simple heuristic, we assume that human-readable names always include a space.
    # However, to avoid confusion for humans, we also don't count spaces at the beginning or end of the string.
    if ' ' not in value.strip():
        return sensitive_domain(value)


def sensitive_domain(domain):
    """
    Checks if user has the admin role, the domain does not match sensitive domains and whitelisted domain patterns.
    :param domain: domain name (str)
    :return:
    """
    if SensitiveDomainPermission().can():
        # User has permission, no need to check anything
        return

    whitelist = current_app.config.get('LEMUR_WHITELISTED_DOMAINS', [])
    if whitelist and not any(re.match(pattern, domain) for pattern in whitelist):
        raise ValidationError('Domain {0} does not match whitelisted domain patterns. '
                              'Contact an administrator to issue the certificate.'.format(domain))

    if any(d.sensitive for d in domain_service.get_by_name(domain)):
        raise ValidationError('Domain {0} has been marked as sensitive. '
                              'Contact an administrator to issue the certificate.'.format(domain))


def encoding(oid_encoding):
    """
    Determines if the specified oid type is valid.
    :param oid_encoding:
    :return:
    """
    valid_types = ['b64asn1', 'string', 'ia5string']
    if oid_encoding.lower() not in [o_type.lower() for o_type in valid_types]:
        raise ValidationError('Invalid Oid Encoding: {0} choose from {1}'.format(oid_encoding, ",".join(valid_types)))


def sub_alt_type(alt_type):
    """
    Determines if the specified subject alternate type is valid.
    :param alt_type:
    :return:
    """
    valid_types = ['DNSName', 'IPAddress', 'uniFormResourceIdentifier', 'directoryName', 'rfc822Name', 'registrationID',
                   'otherName', 'x400Address', 'EDIPartyName']
    if alt_type.lower() not in [a_type.lower() for a_type in valid_types]:
        raise ValidationError('Invalid SubAltName Type: {0} choose from {1}'.format(type, ",".join(valid_types)))


def csr(data):
    """
    Determines if the CSR is valid and allowed.
    :param data:
    :return:
    """
    try:
        request = x509.load_pem_x509_csr(data.encode('utf-8'), default_backend())
    except Exception:
        raise ValidationError('CSR presented is not valid.')

    # Validate common name and SubjectAltNames
    for name in request.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        common_name(name.value)

    try:
        alt_names = request.extensions.get_extension_for_class(x509.SubjectAlternativeName)

        for name in alt_names.value.get_values_for_type(x509.DNSName):
            sensitive_domain(name)
    except x509.ExtensionNotFound:
        pass


def dates(data):
    if not data.get('validity_start') and data.get('validity_end'):
        raise ValidationError('If validity start is specified so must validity end.')

    if not data.get('validity_end') and data.get('validity_start'):
        raise ValidationError('If validity end is specified so must validity start.')

    if data.get('validity_start') and data.get('validity_end'):
        if not current_app.config.get('LEMUR_ALLOW_WEEKEND_EXPIRATION', True):
            if is_weekend(data.get('validity_end')):
                raise ValidationError('Validity end must not land on a weekend.')

        if not data['validity_start'] < data['validity_end']:
            raise ValidationError('Validity start must be before validity end.')

        if data.get('authority'):
            if data.get('validity_start').date() < data['authority'].authority_certificate.not_before.date():
                raise ValidationError('Validity start must not be before {0}'.format(data['authority'].authority_certificate.not_before))

            if data.get('validity_end').date() > data['authority'].authority_certificate.not_after.date():
                raise ValidationError('Validity end must not be after {0}'.format(data['authority'].authority_certificate.not_after))

    return data
