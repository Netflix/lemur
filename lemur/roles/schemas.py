"""
.. module: lemur.roles.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields
from lemur.users.schemas import UserNestedOutputSchema
from lemur.authorities.schemas import AuthorityNestedOutputSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import AssociatedUserSchema, AssociatedAuthoritySchema


class RoleInputSchema(LemurInputSchema):
    id = fields.Integer()
    name = fields.String(required=True)
    username = fields.String()
    password = fields.String()
    description = fields.String()
    authorities = fields.Nested(AssociatedAuthoritySchema, many=True)
    users = fields.Nested(AssociatedUserSchema, many=True)


class RoleOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    description = fields.String()
    third_party = fields.Boolean()
    authorities = fields.Nested(AuthorityNestedOutputSchema, many=True)
    users = fields.Nested(UserNestedOutputSchema, many=True)


class RoleNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    description = fields.String()


role_input_schema = RoleInputSchema()
role_output_schema = RoleOutputSchema()
roles_output_schema = RoleOutputSchema(many=True)
