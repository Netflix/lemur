from marshmallow import fields

from lemur.common.fields import ArrowDateTime
from lemur.common.schema import LemurInputSchema, LemurOutputSchema


class DnsProvidersNestedOutputSchema(LemurOutputSchema):
    __envelope__ = False
    id = fields.Integer()
    name = fields.String()
    provider_type = fields.String()
    description = fields.String()
    api_endpoint = fields.String()
    date_created = ArrowDateTime()
    # credentials are intentionally omitted (they are input-only)


class DnsProvidersNestedInputSchema(LemurInputSchema):
    __envelope__ = False
    name = fields.String()
    description = fields.String()
    provider_type = fields.Dict()


dns_provider_output_schema = DnsProvidersNestedOutputSchema()

dns_provider_input_schema = DnsProvidersNestedInputSchema()
