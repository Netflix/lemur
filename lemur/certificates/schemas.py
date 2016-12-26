"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from marshmallow import fields, validate, validates_schema, post_load, pre_load
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

from lemur.common.fields import ArrowDateTime


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

    validity_start = ArrowDateTime()
    validity_end = ArrowDateTime()
    validity_years = fields.Integer()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)  # deprecated
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    csr = fields.String(validate=validators.csr)
    key_type = fields.String(validate=validate.OneOf(['RSA2048', 'RSA4096']), missing='RSA2048')

    notify = fields.Boolean(default=True)
    rotation = fields.Boolean()

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
    def load_data(self, data):
        if data.get('replacements'):
            data['replaces'] = data['replacements']  # TODO remove when field is deprecated
        return missing.convert_validity_years(data)


class CertificateEditInputSchema(CertificateSchema):
    owner = fields.String()

    notify = fields.Boolean()
    rotation = fields.Boolean()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)  # deprecated
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @pre_load
    def load_data(self, data):
        if data.get('replacements'):
            data['replaces'] = data['replacements']  # TODO remove when field is deprecated
        return data

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
    name = fields.String()
    owner = fields.Email()
    creator = fields.Nested(UserNestedOutputSchema)
    description = fields.String()

    status = fields.Boolean()

    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    active = fields.Boolean()

    rotation = fields.Boolean()
    notify = fields.Boolean()

    # Note aliasing  is the first step in deprecating these fields.
    cn = fields.String()  # deprecated
    common_name = fields.String(attribute='cn')

    not_after = fields.DateTime()  # deprecated
    validity_end = ArrowDateTime(attribute='not_after')

    not_before = fields.DateTime()  # deprecated
    validity_start = ArrowDateTime(attribute='not_before')

    issuer = fields.Nested(AuthorityNestedOutputSchema)


class CertificateCloneSchema(LemurOutputSchema):
    __envelope__ = False
    description = fields.String()
    common_name = fields.String()


class CertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    deleted = fields.Boolean(default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()

    rotation = fields.Boolean()

    # Note aliasing  is the first step in deprecating these fields.
    notify = fields.Boolean()
    active = fields.Boolean(attribute='notify')

    cn = fields.String()
    common_name = fields.String(attribute='cn')

    not_after = fields.DateTime()
    validity_end = ArrowDateTime(attribute='not_after')

    not_before = fields.DateTime()
    validity_start = ArrowDateTime(attribute='not_before')

    owner = fields.Email()
    san = fields.Boolean()
    serial = fields.String()
    signing_algorithm = fields.String()

    status = fields.Boolean()
    user = fields.Nested(UserNestedOutputSchema)

    extensions = fields.Nested(ExtensionSchema)

    # associated objects
    domains = fields.Nested(DomainNestedOutputSchema, many=True)
    destinations = fields.Nested(DestinationNestedOutputSchema, many=True)
    notifications = fields.Nested(NotificationNestedOutputSchema, many=True)
    replaces = fields.Nested(CertificateNestedOutputSchema, many=True)
    authority = fields.Nested(AuthorityNestedOutputSchema)
    roles = fields.Nested(RoleNestedOutputSchema, many=True)
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])
    replaced_by = fields.Nested(CertificateNestedOutputSchema, many=True, attribute='replaced')


class CertificateUploadInputSchema(CertificateCreationSchema):
    name = fields.String()
    notify = fields.Boolean(missing=True)

    private_key = fields.String(validate=validators.private_key)
    body = fields.String(required=True, validate=validators.public_certificate)
    chain = fields.String(validate=validators.public_certificate, missing=None)  # TODO this could be multiple certificates

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    @validates_schema
    def keys(self, data):
        if data.get('destinations'):
            if not data.get('private_key'):
                raise ValidationError('Destinations require private key.')


class CertificateExportInputSchema(LemurInputSchema):
    plugin = fields.Nested(PluginInputSchema)


class CertificateNotificationOutputSchema(LemurOutputSchema):
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    owner = fields.Email()
    user = fields.Nested(UserNestedOutputSchema)
    validity_end = ArrowDateTime(attribute='not_after')
    replaced_by = fields.Nested(CertificateNestedOutputSchema, many=True, attribute='replaced')
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
certificate_edit_input_schema = CertificateEditInputSchema()
certificate_notification_output_schema = CertificateNotificationOutputSchema()
