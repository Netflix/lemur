from marshmallow import fields

from lemur.schemas import (
    EndpointNestedOutputSchema,
    ExtensionSchema
)
from lemur.common.schema import LemurOutputSchema
from lemur.users.schemas import UserNestedOutputSchema

from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema
from lemur.destinations.schemas import DestinationNestedOutputSchema
from lemur.domains.schemas import DomainNestedOutputSchema
from lemur.notifications.schemas import NotificationNestedOutputSchema
from lemur.roles.schemas import RoleNestedOutputSchema
from lemur.policies.schemas import RotationPolicyNestedOutputSchema


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


pending_certificate_output_schema = PendingCertificateOutputSchema()
