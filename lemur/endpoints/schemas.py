"""
.. module: lemur.endpoints.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema


class CipherNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    deprecated = fields.Boolean()
    name = fields.String()


class PolicyNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    ciphers = fields.Nested(CipherNestedOutputSchema, many=True)


class EndpointOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    dnsname = fields.String()
    dns_aliases = fields.List(fields.String())
    source_label = fields.String()
    owner = fields.Email()
    type = fields.String()
    port = fields.Integer()
    active = fields.Boolean()
    certificate = fields.Nested(CertificateNestedOutputSchema)
    certificate_path = fields.String()
    registry_type = fields.String()
    policy = fields.Nested(PolicyNestedOutputSchema)

    issues = fields.List(fields.Dict())


endpoint_output_schema = EndpointOutputSchema()
endpoints_output_schema = EndpointOutputSchema(many=True)
