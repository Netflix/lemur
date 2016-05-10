"""
.. module: lemur.sources.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields

from lemur.schemas import PluginSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema


class SourceInputSchema(LemurInputSchema):
    label = fields.String(required=True)
    options = fields.Dict(load_from='source_options', required=True)
    description = fields.String()
    plugin = fields.Nested(PluginSchema)
    active = fields.Boolean()


class SourceOutputSchema(LemurOutputSchema):
    label = fields.String()
    options = fields.Dict(dump_to='source_options')
    description = fields.String()
    plugin = fields.Nested(PluginSchema)
    fields.Boolean()


source_input_schema = SourceInputSchema()
sources_output_schema = SourceOutputSchema(many=True)
source_output_schema = SourceOutputSchema()
