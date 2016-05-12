"""
.. module: lemur.destinations.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from marshmallow import fields, post_dump
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import PluginInputSchema, PluginOutputSchema


class DestinationInputSchema(LemurInputSchema):
    id = fields.Integer()
    label = fields.String(required=True)
    description = fields.String(required=True)
    active = fields.Boolean()
    plugin = fields.Nested(PluginInputSchema, required=True)


class DestinationOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    active = fields.Boolean()
    plugin = fields.Nested(PluginOutputSchema)
    options = fields.List(fields.Dict())

    @post_dump
    def fill_object(self, data):
        data['plugin']['pluginOptions'] = data['options']
        return data


destination_input_schema = DestinationInputSchema()
destinations_output_schema = DestinationOutputSchema(many=True)
destination_output_schema = DestinationOutputSchema()
