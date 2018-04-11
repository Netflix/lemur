from lemur.common.fields import ArrowDateTime
from lemur.common.schema import LemurOutputSchema

from marshmallow import fields


class DnsProvidersNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    description = fields.String()
    provider_type = fields.String()
    credentials = fields.String()
    api_endpoint = fields.String()
    date_created = ArrowDateTime()
    status = fields.String()
    options = fields.String()


default_output_schema = DnsProvidersNestedOutputSchema()
