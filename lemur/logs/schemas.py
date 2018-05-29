"""
.. module: lemur.logs.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.common.schema import LemurOutputSchema
from lemur.certificates.schemas import CertificateNestedOutputSchema
from lemur.users.schemas import UserNestedOutputSchema


class LogOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    certificate = fields.Nested(CertificateNestedOutputSchema)
    user = fields.Nested(UserNestedOutputSchema)
    logged_at = fields.DateTime()
    log_type = fields.String()


logs_output_schema = LogOutputSchema(many=True)
