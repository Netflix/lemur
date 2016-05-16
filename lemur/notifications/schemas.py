"""
.. module: lemur.notifications.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from marshmallow import fields, post_dump
from lemur.common.schema import LemurInputSchema, LemurOutputSchema
from lemur.schemas import PluginInputSchema, PluginOutputSchema, AssociatedCertificateSchema


class NotificationInputSchema(LemurInputSchema):
    id = fields.Integer()
    label = fields.String(required=True)
    description = fields.String()
    active = fields.Boolean()
    plugin = fields.Nested(PluginInputSchema, required=True)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True, missing=[])


class NotificationOutputSchema(LemurOutputSchema):
    id = fields.Integer()
    label = fields.String()
    description = fields.String()
    active = fields.Boolean()
    options = fields.List(fields.Dict())
    plugin = fields.Nested(PluginOutputSchema)
    certificates = fields.Nested(AssociatedCertificateSchema, many=True, missing=[])

    @post_dump
    def fill_object(self, data):
        data['plugin']['pluginOptions'] = data['options']
        return data


class NotificationNestedOutputSchema(NotificationOutputSchema):
    __envelope__ = False


notification_input_schema = NotificationInputSchema()
notification_output_schema = NotificationOutputSchema()
notifications_output_schema = NotificationOutputSchema(many=True)
