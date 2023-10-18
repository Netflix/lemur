"""
.. module: lemur.api_keys.schemas
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
from flask import g
from marshmallow import fields

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.users.schemas import UserNestedOutputSchema, UserInputSchema


def current_user_id():
    return {
        "id": g.current_user.id,
        "email": g.current_user.email,
        "username": g.current_user.username,
    }


class ApiKeyInputSchema(LemurInputSchema):
    name = fields.String(required=False)
    user = fields.Nested(
        UserInputSchema, missing=current_user_id, default=current_user_id
    )
    ttl = fields.Integer()


class ApiKeyRevokeSchema(LemurInputSchema):
    id = fields.Integer(required=True)
    name = fields.String()
    user = fields.Nested(UserInputSchema, required=True)
    revoked = fields.Boolean()
    ttl = fields.Integer()
    issued_at = fields.Integer(required=False)


class UserApiKeyInputSchema(LemurInputSchema):
    name = fields.String(required=False)
    ttl = fields.Integer()


class ApiKeyOutputSchema(LemurOutputSchema):
    jwt = fields.String()


class ApiKeyDescribedOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    user = fields.Nested(UserNestedOutputSchema)
    ttl = fields.Integer()
    issued_at = fields.Integer()
    revoked = fields.Boolean()


api_key_input_schema = ApiKeyInputSchema()
api_key_revoke_schema = ApiKeyRevokeSchema()
api_key_output_schema = ApiKeyOutputSchema()
api_keys_output_schema = ApiKeyDescribedOutputSchema(many=True)
api_key_described_output_schema = ApiKeyDescribedOutputSchema()
user_api_key_input_schema = UserApiKeyInputSchema()
