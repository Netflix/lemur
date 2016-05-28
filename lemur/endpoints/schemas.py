"""
.. module: lemur.endpoints.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields, post_dump

from lemur.common.schema import LemurOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema


BAD_CIPHERS = [
    'Protocol-SSLv3',
    'Protocol-SSLv2'
    'Protocol-TLSv1'
]


class PolicyNestedOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    ciphers = fields.Dict()

    @post_dump
    def add_warnings(self, data):
        for cipher in data['ciphers']:
            if cipher['name'] in BAD_CIPHERS:
                cipher['deprecated'] = True
        return data


class EndpointOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    dnsname = fields.String()
    owner = fields.Email()
    type = fields.String()
    active = fields.Boolean()
    certificate = fields.Nested(CertificateNestedOutputSchema)
    policy = fields.Nested(PolicyNestedOutputSchema)


endpoint_output_schema = EndpointOutputSchema()
endpoints_output_schema = EndpointOutputSchema(many=True)
