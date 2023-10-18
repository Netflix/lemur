"""
.. module: lemur.users.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import re

from flask import current_app
from marshmallow import fields, validates, ValidationError

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import (
    AssociatedRoleSchema,
    AssociatedCertificateSchema,
    AssociatedAuthoritySchema,
)


class UserInputSchema(LemurInputSchema):
    id = fields.Integer()
    username = fields.String(required=True)
    email = fields.Email(required=True)
    password = fields.String()
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True, missing=[])
    certificates = fields.Nested(AssociatedCertificateSchema, many=True, missing=[])
    authorities = fields.Nested(AssociatedAuthoritySchema, many=True, missing=[])


class UserCreateInputSchema(UserInputSchema):
    @validates('password')
    def validate_password(self, value):
        if current_app.config.get('CHECK_PASSWORD_STRENGTH', True):
            # At least 12 characters
            if len(value) < 12:
                raise ValidationError('Password must be at least 12 characters long.')

            # A mixture of both uppercase and lowercase letters
            if not any(map(str.isupper, value)) or not any(map(str.islower, value)):
                raise ValidationError('Password must contain both uppercase and lowercase characters.')

            # A mixture of letters and numbers
            if not any(map(str.isdigit, value)):
                raise ValidationError('Password must contain at least one digit.')

            # Inclusion of at least one special character
            if not re.findall(r'[!@#?\]]', value):
                raise ValidationError('Password must contain at least one special character (!@#?]).')


class UserOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    username = fields.String()
    email = fields.Email()
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True)
    profile_picture = fields.String()


user_input_schema = UserInputSchema()
user_create_input_schema = UserCreateInputSchema()
user_output_schema = UserOutputSchema()
users_output_schema = UserOutputSchema(many=True)


class UserNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    username = fields.String()
    email = fields.Email()
    active = fields.Boolean()
