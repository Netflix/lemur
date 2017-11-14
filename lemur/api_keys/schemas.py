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


class ApiKeyRevokeInputSchema(LemurInputSchema):
    name = fields.String()
    revoked = fields.Boolean()
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
api_key_revoke_input_schema = ApiKeyRevokeInputSchema()
api_key_output_schema = ApiKeyOutputSchema()
api_keys_output_schema = ApiKeyInputSchema(many=True)
api_key_described_output_schema = ApiKeyDescribedOutputSchema()
