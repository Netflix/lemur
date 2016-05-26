"""
.. module: lemur.endpoints.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema


class EndpointOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    description = fields.String()
    name = fields.String()
    owner = fields.Email()
    type = fields.String()
    active = fields.Boolean()
    certificate = fields.Nested(CertificateNestedOutputSchema)


endpoint_output_schema = EndpointOutputSchema()
endpoints_output_schema = EndpointOutputSchema(many=True)
