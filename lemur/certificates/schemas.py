"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from marshmallow import fields, validates_schema
from marshmallow.exceptions import ValidationError

from lemur.schemas import AssociatedAuthoritySchema, AssociatedDestinationSchema, AssociatedCertificateSchema, \
    AssociatedNotificationSchema, PluginInputSchema, ExtensionSchema

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.notifications.schemas import NotificationNestedOutputSchema
# from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.users.schemas import UserNestedOutputSchema

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.common import validators


class CertificateInputSchema(LemurInputSchema):
    name = fields.String()
    owner = fields.Email(required=True)
    description = fields.String()
    common_name = fields.String(required=True, validate=validators.sensitive_domain)
    authority = fields.Nested(AssociatedAuthoritySchema, required=True)

    validity_start = fields.DateTime()
    validity_end = fields.DateTime()
    validity_years = fields.Integer()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)

    csr = fields.String(validate=validators.csr)

    # certificate body fields
    organizational_unit = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'))
    organization = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'))
    location = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_LOCATION'))
    country = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_COUNTRY'))
    state = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_STATE'))

    extensions = fields.Nested(ExtensionSchema)

    @validates_schema
    def validate_dates(self, data):
        validators.dates(data)


class CertificateEditInputSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String()
    active = fields.Boolean()
    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)


class CertificateNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    active = fields.Boolean()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    description = fields.String()
    name = fields.String()
    cn = fields.String()
    not_after = fields.DateTime()
    not_before = fields.DateTime()
    owner = fields.Email()
    status = fields.Boolean()
    creator = fields.Nested(UserNestedOutputSchema)
    issuer = fields.Nested(AuthorityNestedOutputSchema)


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
    cn = fields.String()
    not_after = fields.DateTime()
    not_before = fields.DateTime()
    owner = fields.Email()
    san = fields.Boolean()
    serial = fields.String()
    signing_algorithm = fields.String()
    status = fields.Boolean()
    user = fields.Nested(UserNestedOutputSchema)
    # domains = fields.Nested(DomainNestedOutputSchema)
    destinations = fields.Nested(DestinationNestedOutputSchema, many=True)
    notifications = fields.Nested(NotificationNestedOutputSchema, many=True)
    replaces = fields.Nested(CertificateNestedOutputSchema, many=True)
    authority = fields.Nested(AuthorityNestedOutputSchema)


class CertificateUploadInputSchema(LemurInputSchema):
    name = fields.String()
    owner = fields.Email(required=True)
    description = fields.String()
    active = fields.Boolean(missing=True)

    private_key = fields.String(validate=validators.private_key)
    public_cert = fields.String(required=True, validate=validators.public_certificate)
    chain = fields.String(validate=validators.public_certificate)  # TODO this could be multiple certificates

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)

    @validates_schema
    def keys(self, data):
        if data.get('destinations'):
            if not data.get('private_key'):
                raise ValidationError('Destinations require private key.')


class CertificateExportInputSchema(LemurInputSchema):
    export = fields.Nested(PluginInputSchema)


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
certificate_edit_input_schema = CertificateEditInputSchema()
