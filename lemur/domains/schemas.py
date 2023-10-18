"""
.. module: lemur.domains.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import AssociatedCertificateSchema


# from lemur.certificates.schemas import CertificateNestedOutputSchema


class DomainInputSchema(LemurInputSchema):
    id = fields.Integer()
    name = fields.String(required=True)
    sensitive = fields.Boolean(missing=False)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True, missing=[])


class DomainOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    name = fields.String()
    sensitive = fields.Boolean()
    # certificates = fields.Nested(CertificateNestedOutputSchema, many=True, missing=[])


class DomainNestedOutputSchema(DomainOutputSchema):
    __envelope__ = False


domain_input_schema = DomainInputSchema()
domain_output_schema = DomainOutputSchema()
domains_output_schema = DomainOutputSchema(many=True)
