"""
.. module: lemur.certificates.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from marshmallow import fields, validate, validates_schema, post_load, pre_load
from marshmallow.exceptions import ValidationError

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.common import missing, utils, validators
from lemur.common.fields import ArrowDateTime, Hex
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.constants import CERTIFICATE_KEY_TYPES
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.dns_providers.schemas import DnsProvidersNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.notifications import service as notification_service
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.policies.schemas import RotationPolicyNestedOutputSchema
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.schemas import (
    AssociatedAuthoritySchema,
    AssociatedDestinationSchema,
    AssociatedCertificateSchema,
    AssociatedNotificationSchema,
    AssociatedDnsProviderSchema,
    PluginInputSchema,
    ExtensionSchema,
    AssociatedRoleSchema,
    EndpointNestedOutputSchema,
    AssociatedRotationPolicySchema,
)
from lemur.users.schemas import UserNestedOutputSchema


class CertificateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String(missing='', allow_none=True)


class CertificateCreationSchema(CertificateSchema):
    @post_load
    def default_notification(self, data):
        if not data['notifications']:
            data['notifications'] += notification_service.create_default_expiration_notifications(
                "DEFAULT_{0}".format(data['owner'].split('@')[0].upper()),
                [data['owner']],
            )

            data['notifications'] += notification_service.create_default_expiration_notifications(
                'DEFAULT_SECURITY',
                current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL'),
                current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL_INTERVALS', None)
            )
        return data


class CertificateInputSchema(CertificateCreationSchema):
    name = fields.String()
    common_name = fields.String(required=True, validate=validators.common_name)
    authority = fields.Nested(AssociatedAuthoritySchema, required=True)

    validity_start = ArrowDateTime(allow_none=True)
    validity_end = ArrowDateTime(allow_none=True)
    validity_years = fields.Integer(allow_none=True)

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    replacements = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)  # deprecated
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)
    dns_provider = fields.Nested(AssociatedDnsProviderSchema, missing=None, allow_none=True, required=False)

    csr = fields.String(allow_none=True, validate=validators.csr)

    key_type = fields.String(
        validate=validate.OneOf(CERTIFICATE_KEY_TYPES),
        missing='RSA2048')

    notify = fields.Boolean(default=True)
    rotation = fields.Boolean()
    rotation_policy = fields.Nested(AssociatedRotationPolicySchema, missing={'name': 'default'}, allow_none=True,
                                    default={'name': 'default'})

    # certificate body fields
    organizational_unit = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'))
    organization = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'))
    location = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_LOCATION'))
    country = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_COUNTRY'))
    state = fields.String(missing=lambda: current_app.config.get('LEMUR_DEFAULT_STATE'))

    extensions = fields.Nested(ExtensionSchema)

    @validates_schema
    def validate_authority(self, data):
        if not data['authority'].active:
            raise ValidationError("The authority is inactive.", ['authority'])

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
            data['notifications'] += notification_service.create_default_expiration_notifications(notification_name,
                                                                                                  [data['owner']])
        return data


class CertificateNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    owner = fields.Email()
    creator = fields.Nested(UserNestedOutputSchema)
    description = fields.String()

    status = fields.String()

    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    csr = fields.String()
    active = fields.Boolean()

    rotation = fields.Boolean()
    notify = fields.Boolean()
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)

    # Note aliasing is the first step in deprecating these fields.
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
    external_id = fields.String()
    bits = fields.Integer()
    body = fields.String()
    chain = fields.String()
    csr = fields.String()
    deleted = fields.Boolean(default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    dns_provider_id = fields.Integer(required=False, allow_none=True)
    date_created = ArrowDateTime()
    resolved = fields.Boolean(required=False, allow_none=True)
    resolved_cert_id = fields.Integer(required=False, allow_none=True)

    rotation = fields.Boolean()

    # Note aliasing is the first step in deprecating these fields.
    notify = fields.Boolean()
    active = fields.Boolean(attribute='notify')

    cn = fields.String()
    common_name = fields.String(attribute='cn')
    distinguished_name = fields.String()

    not_after = fields.DateTime()
    validity_end = ArrowDateTime(attribute='not_after')

    not_before = fields.DateTime()
    validity_start = ArrowDateTime(attribute='not_before')

    owner = fields.Email()
    san = fields.Boolean()
    serial = fields.String()
    serial_hex = Hex(attribute='serial')
    signing_algorithm = fields.String()

    status = fields.String()
    user = fields.Nested(UserNestedOutputSchema)

    extensions = fields.Nested(ExtensionSchema)

    # associated objects
    domains = fields.Nested(DomainNestedOutputSchema, many=True)
    destinations = fields.Nested(DestinationNestedOutputSchema, many=True)
    notifications = fields.Nested(NotificationNestedOutputSchema, many=True)
    replaces = fields.Nested(CertificateNestedOutputSchema, many=True)
    authority = fields.Nested(AuthorityNestedOutputSchema)
    dns_provider = fields.Nested(DnsProvidersNestedOutputSchema)
    roles = fields.Nested(RoleNestedOutputSchema, many=True)
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, missing=[])
    replaced_by = fields.Nested(CertificateNestedOutputSchema, many=True, attribute='replaced')
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)


class CertificateUploadInputSchema(CertificateCreationSchema):
    name = fields.String()
    authority = fields.Nested(AssociatedAuthoritySchema, required=False)
    notify = fields.Boolean(missing=True)
    external_id = fields.String(missing=None, allow_none=True)
    private_key = fields.String()
    body = fields.String(required=True)
    chain = fields.String(validate=validators.public_certificate, missing=None,
                          allow_none=True)  # TODO this could be multiple certificates

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, missing=[], many=True)

    # Upload behavior
    allow_duplicate = fields.Boolean(default=False)     # TODO: Need a user interface flag for this

    @validates_schema
    def keys(self, data):
        if data.get('destinations'):
            if not data.get('private_key'):
                raise ValidationError('Destinations require private key.')

    @validates_schema
    def validate_cert_private_key(self, data):
        cert = None
        key = None
        if data.get('body'):
            try:
                cert = utils.parse_certificate(data['body'])
            except ValueError:
                raise ValidationError("Public certificate presented is not valid.", field_names=['body'])

            if not data.get('allow_duplicate'):
                validators.validate_duplicate_cert(cert)

        if data.get('private_key'):
            try:
                key = utils.parse_private_key(data['private_key'])
            except ValueError:
                raise ValidationError("Private key presented is not valid.", field_names=['private_key'])

        if cert and key:
            # Throws ValidationError
            validators.verify_private_key_match(key, cert)


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


class CertificateRevokeSchema(LemurInputSchema):
    comments = fields.String()


certificate_input_schema = CertificateInputSchema()
certificate_output_schema = CertificateOutputSchema()
certificates_output_schema = CertificateOutputSchema(many=True)
certificate_upload_input_schema = CertificateUploadInputSchema()
certificate_export_input_schema = CertificateExportInputSchema()
certificate_edit_input_schema = CertificateEditInputSchema()
certificate_notification_output_schema = CertificateNotificationOutputSchema()
certificate_revoke_schema = CertificateRevokeSchema()
