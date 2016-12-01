"""
.. module: lemur.defaults.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields
from lemur.common.schema import LemurOutputSchema
from lemur.authorities.schemas import AuthorityNestedOutputSchema


class DefaultOutputSchema(LemurOutputSchema):
    __envelope__ = False
    authority = fields.Nested(AuthorityNestedOutputSchema)
    country = fields.String()
    state = fields.String()
    location = fields.String()
    organization = fields.String()
    organizationalUnit = fields.String()

default_output_schema = DefaultOutputSchema()
