"""
.. module: lemur.notifications.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import PluginSchema, AssociatedCertificateSchema


class NotificationInputSchema(LemurInputSchema):
    label = fields.String()
    description = fields.String()
    options = fields.Dict()
    active = fields.Boolean()
    plugin = fields.Nested(PluginSchema)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True)


class NotificationOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    options = fields.Dict(dump_to='notification_options')
    active = fields.Boolean()
    plugin = fields.Nested(PluginSchema)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True)


notification_input_schema = NotificationInputSchema()
notification_output_schema = NotificationOutputSchema()
notifications_output_schema = NotificationOutputSchema(many=True)
