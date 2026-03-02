"""
.. module: lemur.users.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from marshmallow import fields
from marshmallow.exceptions import ValidationError

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.common.fields import ArrowDateTime
from lemur.schemas import (
    AssociatedRoleSchema,
    AssociatedCertificateSchema,
    AssociatedAuthoritySchema,
)


class UserInputSchema(LemurInputSchema):
    id = fields.Integer()
    username = fields.String(required=True)
    email = fields.Email(required=True)
    password = fields.String()  # TODO add complexity requirements
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True, missing=[])
    certificates = fields.Nested(AssociatedCertificateSchema, many=True, missing=[])
    authorities = fields.Nested(AssociatedAuthoritySchema, many=True, missing=[])


class UserOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    username = fields.String()
    email = fields.Email()
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True)
    profile_picture = fields.String()


user_input_schema = UserInputSchema()
user_output_schema = UserOutputSchema()
users_output_schema = UserOutputSchema(many=True)


class UserNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    username = fields.String()
    email = fields.Email()
    active = fields.Boolean()


def validate_expires_in_hours(val):
    if not (0 < val <= 24):
        raise ValidationError("expires_in_hours must be between 1 and 24 (1 day).")


class BreakGlassGrantInputSchema(LemurInputSchema):
    """Request body for granting temporary break-glass to a user (admin only)."""

    expires_in_hours = fields.Integer(required=True, validate=validate_expires_in_hours)


class BreakGlassGrantOutputSchema(LemurOutputSchema):
    """Response for active temporary break-glass grant."""

    id = fields.Integer()
    user_id = fields.Integer()
    granted_by_id = fields.Integer(allow_none=True)
    expires_at = ArrowDateTime()


break_glass_grant_input_schema = BreakGlassGrantInputSchema()
break_glass_grant_output_schema = BreakGlassGrantOutputSchema()
