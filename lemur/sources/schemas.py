"""
.. module: lemur.sources.schemas
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields, post_dump

from lemur.schemas import PluginInputSchema, PluginOutputSchema
from lemur.common.schema import LemurInputSchema, LemurOutputSchema


class SourceInputSchema(LemurInputSchema):
    id = fields.Integer()
    label = fields.String(required=True)
    description = fields.String()
    plugin = fields.Nested(PluginInputSchema)
    active = fields.Boolean()


class SourceOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    plugin = fields.Nested(PluginOutputSchema)
    options = fields.List(fields.Dict())
    fields.Boolean()

    @post_dump
    def fill_object(self, data):
        if data:
            data["plugin"]["pluginOptions"] = data["options"]
        return data


source_input_schema = SourceInputSchema()
sources_output_schema = SourceOutputSchema(many=True)
source_output_schema = SourceOutputSchema()
