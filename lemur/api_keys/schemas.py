"""
.. module: lemur.api_keys.schemas
    :platform: Unix
    :copyright: (c) 2017 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurInputSchema, LemurOutputSchema


class ApiKeyInputSchema(LemurInputSchema):
    name = fields.String(required=False)
    user_id = fields.Integer()
    ttl = fields.Integer()


class ApiKeyRevokeSchema(LemurInputSchema):
    id = fields.Integer(required=False)
    name = fields.String()
    user_id = fields.Integer(required=False)
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
    user_id = fields.Integer()
    ttl = fields.Integer()
    issued_at = fields.Integer()
    revoked = fields.Boolean()


api_key_input_schema = ApiKeyInputSchema()
api_key_revoke_schema = ApiKeyRevokeSchema()
api_key_output_schema = ApiKeyOutputSchema()
api_keys_output_schema = ApiKeyDescribedOutputSchema(many=True)
api_key_described_output_schema = ApiKeyDescribedOutputSchema()
user_api_key_input_schema = UserApiKeyInputSchema()
