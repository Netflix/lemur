"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

import arrow

from marshmallow import fields, validates_schema, pre_load, post_dump
from marshmallow.exceptions import ValidationError

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from lemur.auth.permissions import SensitiveDomainPermission
from lemur.schemas import AssociatedAuthoritySchema, AssociatedDestinationSchema, AssociatedCertificateSchema, \
    AssociatedNotificationSchema, PluginSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema, LemurSchema

from lemur.domains import service as domain_service


def validate_public_certificate(body):
    """
    Determines if specified string is valid public certificate.

    :param body:
    :return:
    """
    try:
        x509.load_pem_x509_certificate(bytes(body), default_backend())
    except Exception:
        raise ValidationError('Public certificate presented is not valid.')


def validate_private_key(key):
    """
    User to validate that a given string is a RSA private key

    :param key:
    :return: :raise ValueError:
    """
    try:
        serialization.load_pem_private_key(bytes(key), None, backend=default_backend())
    except Exception:
        raise ValidationError('Private key presented is not valid.')


def validate_domain(domain):
    """
    Determines if domain has been marked as sensitive.
    :param domain:
    :return:
    """
    domains = domain_service.get_by_name(domain)
    for domain in domains:
        # we only care about non-admins
        if not SensitiveDomainPermission().can():
            if domain.sensitive:
                raise ValidationError(
                    'Domain {0} has been marked as sensitive, contact and administrator \
                    to issue the certificate.'.format(domain))


def validate_oid_type(oid_type):
    """
    Determines if the specified oid type is valid.
    :param oid_type:
    :return:
    """
    valid_types = ['b64asn1', 'string', 'ia5string']
    if oid_type.lower() not in [o_type.lower() for o_type in valid_types]:
        raise ValidationError('Invalid Oid Type: {0} choose from {1}'.format(oid_type, ",".join(valid_types)))


def validate_sub_alt_type(alt_type):
    """
    Determines if the specified subject alternate type is valid.
    :param alt_type:
    :return:
    """
    valid_types = ['DNSName', 'IPAddress', 'uniFormResourceIdentifier', 'directoryName', 'rfc822Name', 'registrationID',
                   'otherName', 'x400Address', 'EDIPartyName']
    if alt_type.lower() not in [a_type.lower() for a_type in valid_types]:
        raise ValidationError('Invalid SubAltName Type: {0} choose from {1}'.format(type, ",".join(valid_types)))


def validate_csr(data):
    """
    Determines if the CSR is valid.
    :param data:
    :return:
    """
    try:
        x509.load_pem_x509_csr(bytes(data), default_backend())
    except Exception:
        raise ValidationError('CSR presented is not valid.')


class BaseExtensionSchema(LemurSchema):
    @pre_load(pass_many=True)
    def preprocess(self, data, many):
        return self.under(data, many=many)

    @post_dump(pass_many=True)
    def post_process(self, data, many):
        if data:
            data = self.camel(data, many=many)
        return data


class BasicConstraintsSchema(BaseExtensionSchema):
    pass


class AuthorityIdentifierSchema(BaseExtensionSchema):
    use_authority_cert = fields.Boolean()


class AuthorityKeyIdentifierSchema(BaseExtensionSchema):
    use_key_identifier = fields.Boolean()


class CertificateInfoAccessSchema(BaseExtensionSchema):
    include_aia = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeAIA': data['include_aia']}


class KeyUsageSchema(BaseExtensionSchema):
    use_crl_sign = fields.Boolean()
    use_data_encipherment = fields.Boolean()
    use_decipher_only = fields.Boolean()
    use_encipher_only = fields.Boolean()
    use_key_encipherment = fields.Boolean()
    use_digital_signature = fields.Boolean()
    use_non_repudiation = fields.Boolean()


class ExtendedKeyUsageSchema(BaseExtensionSchema):
    use_server_authentication = fields.Boolean()
    use_client_authentication = fields.Boolean()
    use_eap_over_lan = fields.Boolean()
    use_eap_over_ppp = fields.Boolean()
    use_ocsp_signing = fields.Boolean()
    use_smart_card_authentication = fields.Boolean()
    use_timestamping = fields.Boolean()


class SubjectKeyIdentifierSchema(BaseExtensionSchema):
    include_ski = fields.Boolean()

    @post_dump
    def handle_keys(self, data):
        return {'includeSKI': data['include_ski']}


class SubAltNameSchema(BaseExtensionSchema):
    name_type = fields.String(validate=validate_sub_alt_type)
    value = fields.String()

    @validates_schema
    def check_sensitive(self, data):
        if data['name_type'] == 'DNSName':
            validate_domain(data['value'])


class SubAltNamesSchema(BaseExtensionSchema):
    names = fields.Nested(SubAltNameSchema, many=True)


class CustomOIDSchema(BaseExtensionSchema):
    oid = fields.String()
    oid_type = fields.String(validate=validate_oid_type)
    value = fields.String()


class ExtensionSchema(BaseExtensionSchema):
    basic_constraints = fields.Nested(BasicConstraintsSchema)
    key_usage = fields.Nested(KeyUsageSchema)
    extended_key_usage = fields.Nested(ExtendedKeyUsageSchema)
    subject_key_identifier = fields.Nested(SubjectKeyIdentifierSchema)
    sub_alt_names = fields.Nested(SubAltNamesSchema)
    authority_identifier = fields.Nested(AuthorityIdentifierSchema)
    authority_key_identifier = fields.Nested(AuthorityKeyIdentifierSchema)
    certificate_info_access = fields.Nested(CertificateInfoAccessSchema)
    custom = fields.List(fields.Nested(CustomOIDSchema))


class CertificateInputSchema(LemurInputSchema):
    name = fields.String()
    owner = fields.Email(required=True)
    description = fields.String()
    common_name = fields.String(required=True, validate=validate_domain)
    authority = fields.Nested(AssociatedAuthoritySchema, required=True)

    validity_start = fields.DateTime()
    validity_end = fields.DateTime()
    validity_years = fields.Integer()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)

    csr = fields.String(validate=validate_csr)

    # certificate body fields
    organizational_unit = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'))
    organization = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'))
    location = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_LOCATION'))
    country = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_COUNTRY'))
    state = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_STATE'))

    extensions = fields.Nested(ExtensionSchema)

    @validates_schema
    def validate_dates(self, data):
        if not data.get('validity_start') and data.get('validity_end'):
            raise ValidationError('If validity start is specified so must validity end.')

        if not data.get('validity_end') and data.get('validity_start'):
            raise ValidationError('If validity end is specified so must validity start.')

        if data.get('validity_end') and data.get('validity_years'):
            raise ValidationError('Cannot specify both validity end and validity years.')

        if data.get('validity_start') and data.get('validity_end'):
            if not data['validity_start'] < data['validity_end']:
                raise ValidationError('Validity start must be before validity end.')

            if data.get('validity_start').replace(tzinfo=None) < data['authority'].not_before:
                raise ValidationError('Validity start must not be before {0}'.format(data['authority'].not_before))

            if data.get('validity_end').replace(tzinfo=None) > data['authority'].not_after:
                raise ValidationError('Validity end must not be after {0}'.format(data['authority'].not_after))

        if data.get('validity_years'):
            now = arrow.utcnow()
            end = now.replace(years=+data['validity_years'])

            if now.naive < data['authority'].not_before:
                raise ValidationError('Validity start must not be before {0}'.format(data['authority'].not_before))

            if end.naive > data['authority'].not_after:
                raise ValidationError('Validity end must not be after {0}'.format(data['authority'].not_after))


class CertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    active = fields.Boolean()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    deleted = fields.Boolean(default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    not_after = fields.DateTime()
    not_before = fields.DateTime()
    owner = fields.Email()
    san = fields.Boolean()
    serial = fields.String()
    signing_algorithm = fields.String()
    status = fields.Boolean()


class CertificateUploadInputSchema(LemurInputSchema):
    name = fields.String()
    owner = fields.Email(required=True)
    description = fields.String()
    active = fields.Boolean(missing=True)

    private_key = fields.String(validate=validate_private_key)
    public_cert = fields.String(required=True, validate=validate_public_certificate)
    chain = fields.String(validate=validate_public_certificate)

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)

    @validates_schema
    def keys(self, data):
        if data.get('destinations'):
            if not data.get('private_key'):
                raise ValidationError('Destinations require private key.')


class CertificateExportInputSchema(LemurInputSchema):
    export = fields.Nested(PluginSchema)


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
