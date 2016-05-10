"""
.. module: lemur.users.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import AssociatedRoleSchema, AssociatedCertificateSchema, AssociatedAuthoritySchema


class UserInputSchema(LemurInputSchema):
    username = fields.String(required=True)
    email = fields.Email(required=True)
    password = fields.String(required=True)  # TODO add complexity requirements
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True)
    authorities = fields.Nested(AssociatedAuthoritySchema, many=True)


class UserOutputSchema(LemurOutputSchema):
    username = fields.String()
    email = fields.Email()
    password = fields.String()
    active = fields.Boolean()
    roles = fields.Nested(AssociatedRoleSchema, many=True)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True)
    authorities = fields.Nested(AssociatedAuthoritySchema, many=True)


user_input_schema = UserInputSchema()
user_output_schema = UserOutputSchema()
users_output_schema = UserOutputSchema(many=True)
