from lemur.common.fields import ArrowDateTime
from lemur.common.schema import LemurOutputSchema

from marshmallow import fields


class DnsProvidersNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    provider_type = fields.String()
    description = fields.String()
    credentials = fields.String()
    api_endpoint = fields.String()
    date_created = ArrowDateTime()


dns_provider_schema = DnsProvidersNestedOutputSchema()
