"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from marshmallow import fields, validates_schema, post_load, pre_load
from marshmallow.exceptions import ValidationError

from lemur.schemas import AssociatedAuthoritySchema, AssociatedDestinationSchema, AssociatedCertificateSchema, \
    AssociatedNotificationSchema, PluginInputSchema, ExtensionSchema, AssociatedRoleSchema, EndpointNestedOutputSchema

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.users.schemas import UserNestedOutputSchema

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.common import validators, missing
from lemur.notifications import service as notification_service


class CertificateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String()


class CertificateCreationSchema(CertificateSchema):
    @post_load
    def default_notification(self, data):
        if not data['notifications']:
            notification_name = "DEFAULT_{0}".format(data['owner'].split('@')[0].upper())
            data['notifications'] += notification_service.create_default_expiration_notifications(notification_name, [data['owner']])

        notification_name = 'DEFAULT_SECURITY'
        data['notifications'] += notification_service.create_default_expiration_notifications(notification_name, current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL'))
        return data


class CertificateInputSchema(CertificateCreationSchema):
    name = fields.String()
    common_name = fields.String(required=True, validate=validators.sensitive_domain)
    authority = fields.Nested(AssociatedAuthoritySchema, required=True)

    validity_start = fields.DateTime()
    validity_end = fields.DateTime()
    validity_years = fields.Integer()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

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

    @pre_load
    def ensure_dates(self, data):
        return missing.convert_validity_years(data)


class CertificateEditInputSchema(CertificateSchema):
    notify = fields.Boolean()
    owner = fields.String()
    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @post_load
    def enforce_notifications(self, data):
        """
        Ensures that when an owner changes, default notifications are added for the new owner.
        Old owner notifications are retained unless explicitly removed.
        :param data:
        :return:
        """
        if data['owner']:
            notification_name = "DEFAULT_{0}".format(data['owner'].split('@')[0].upper())
            data['notifications'] += notification_service.create_default_expiration_notifications(notification_name, [data['owner']])
        return data


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


class CertificateCloneSchema(LemurOutputSchema):
    __envelope__ = False
    description = fields.String()
    common_name = fields.String()


class CertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    active = fields.Boolean()
    notify = fields.Boolean()
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
    domains = fields.Nested(DomainNestedOutputSchema, many=True)
    destinations = fields.Nested(DestinationNestedOutputSchema, many=True)
    notifications = fields.Nested(NotificationNestedOutputSchema, many=True)
    replaces = fields.Nested(CertificateNestedOutputSchema, many=True)
    authority = fields.Nested(AuthorityNestedOutputSchema)
    roles = fields.Nested(RoleNestedOutputSchema, many=True)
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])


class CertificateUploadInputSchema(CertificateCreationSchema):
    name = fields.String()
    notify = fields.Boolean(missing=True)

    private_key = fields.String(validate=validators.private_key)
    body = fields.String(required=True, validate=validators.public_certificate)
    chain = fields.String(validate=validators.public_certificate)  # TODO this could be multiple certificates

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @validates_schema
    def keys(self, data):
        if data.get('destinations'):
            if not data.get('private_key'):
                raise ValidationError('Destinations require private key.')


class CertificateExportInputSchema(LemurInputSchema):
    plugin = fields.Nested(PluginInputSchema)


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
certificate_edit_input_schema = CertificateEditInputSchema()
