from marshmallow import fields, post_load

from lemur.schemas import (
    AssociatedCertificateSchema,
    AssociatedDestinationSchema,
    AssociatedNotificationSchema,
    AssociatedRoleSchema,
    EndpointNestedOutputSchema,
    ExtensionSchema
)

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.users.schemas import UserNestedOutputSchema
from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.policies.schemas import RotationPolicyNestedOutputSchema

from lemur.notifications import service as notification_service


class PendingCertificateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String(missing='', allow_none=True)


class PendingCertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    external_id = fields.String()
    csr = fields.String()
    chain = fields.String()
    deleted = fields.Boolean(default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    number_attempts = fields.Integer()
    date_created = fields.Date()

    rotation = fields.Boolean()

    # Note aliasing is the first step in deprecating these fields.
    notify = fields.Boolean()
    active = fields.Boolean(attribute='notify')

    cn = fields.String()
    common_name = fields.String(attribute='cn')

    owner = fields.Email()

    status = fields.String()
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
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)


class PendingCertificateEditInputSchema(PendingCertificateSchema):
    owner = fields.String()

    notify = fields.Boolean()
    rotation = fields.Boolean()

    destinations = fields.Nested(AssociatedDestinationSchema, missing=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, missing=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, missing=[], many=True)
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


pending_certificate_output_schema = PendingCertificateOutputSchema()
pending_certificate_edit_input_schema = PendingCertificateEditInputSchema()
