"""
.. module: lemur.destinations.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from marshmallow import fields
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import PluginSchema


class DestinationInputSchema(LemurInputSchema):
    label = fields.String(required=True)
    options = fields.Dict(required=True)
    description = fields.String()
    plugin = fields.Nested(PluginSchema, required=True)


class DestinationOutputSchema(LemurOutputSchema):
    label = fields.String()
    options = fields.Dict(dump_to='destination_options')
    description = fields.String()


destination_input_schema = DestinationInputSchema()
destinations_output_schema = DestinationOutputSchema(many=True)
destination_output_schema = DestinationOutputSchema()
