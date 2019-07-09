"""
.. module: lemur.users.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

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
