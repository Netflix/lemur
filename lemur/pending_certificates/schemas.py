from marshmallow import fields, validates_schema, post_load
from marshmallow.exceptions import ValidationError

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema
from lemur.common import utils, validators
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.notifications import service as notification_service
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.policies.schemas import RotationPolicyNestedOutputSchema
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.schemas import (
    AssociatedCertificateSchema,
    AssociatedDestinationSchema,
    AssociatedNotificationSchema,
    AssociatedRoleSchema,
    EndpointNestedOutputSchema,
    ExtensionSchema,
)
from lemur.users.schemas import UserNestedOutputSchema


class PendingCertificateSchema(LemurInputSchema):
    owner = fields.Email(required=True)
    description = fields.String(load_default="", allow_none=True)


class PendingCertificateOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    external_id = fields.String()
    csr = fields.String()
    chain = fields.String()
    deleted = fields.Boolean(load_default=False)
    description = fields.String()
    issuer = fields.String()
    name = fields.String()
    number_attempts = fields.Integer()
    date_created = fields.Date()
    last_updated = fields.Date()
    resolved = fields.Boolean(required=False)
    resolved_cert_id = fields.Integer(required=False)

    rotation = fields.Boolean()

    # Note aliasing is the first step in deprecating these fields.
    active = fields.Boolean(attribute="notify")

    common_name = fields.String(attribute="cn")

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
    endpoints = fields.Nested(EndpointNestedOutputSchema, many=True, load_default=[])
    replaced_by = fields.Nested(
        CertificateNestedOutputSchema, many=True, attribute="replaced"
    )
    rotation_policy = fields.Nested(RotationPolicyNestedOutputSchema)


class PendingCertificateEditInputSchema(PendingCertificateSchema):
    owner = fields.Email()

    notify = fields.Boolean()
    rotation = fields.Boolean()

    destinations = fields.Nested(AssociatedDestinationSchema, load_default=[], many=True)
    notifications = fields.Nested(AssociatedNotificationSchema, load_default=[], many=True)
    replaces = fields.Nested(AssociatedCertificateSchema, load_default=[], many=True)
    roles = fields.Nested(AssociatedRoleSchema, load_default=[], many=True)

    @post_load
    def enforce_notifications(self, data):
        """
        Ensures that when an owner changes, default notifications are added for the new owner.
        Old owner notifications are retained unless explicitly removed.
        :param data:
        :return:
        """
        if data["owner"]:
            notification_name = "DEFAULT_{}".format(
                data["owner"].split("@")[0].upper()
            )
            data[
                "notifications"
            ] += notification_service.create_default_expiration_notifications(
                notification_name, [data["owner"]]
            )
        return data


class PendingCertificateCancelSchema(LemurInputSchema):
    note = fields.String()


class PendingCertificateUploadInputSchema(LemurInputSchema):
    external_id = fields.String(load_default=None, allow_none=True)
    body = fields.String(required=True)
    chain = fields.String(load_default=None, allow_none=True)

    @validates_schema
    def validate_cert_chain(self, data):
        cert = None
        if data.get("body"):
            try:
                cert = utils.parse_certificate(data["body"])
            except ValueError:
                raise ValidationError(
                    "Public certificate presented is not valid.", field_names=["body"]
                )

        if data.get("chain"):
            try:
                chain = utils.parse_cert_chain(data["chain"])
            except ValueError:
                raise ValidationError(
                    "Invalid certificate in certificate chain.", field_names=["chain"]
                )

            # Throws ValidationError
            validators.verify_cert_chain([cert] + chain)


pending_certificate_output_schema = PendingCertificateOutputSchema()
pending_certificate_edit_input_schema = PendingCertificateEditInputSchema()
pending_certificate_cancel_schema = PendingCertificateCancelSchema()
pending_certificate_upload_input_schema = PendingCertificateUploadInputSchema()
