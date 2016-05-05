"""
.. module: lemur.schemas
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from marshmallow import fields, post_load
from lemur.authorities.models import Authority
from lemur.destinations.models import Destination
from lemur.certificates.models import Certificate
from lemur.notifications.models import Notification
from lemur.common.schema import LemurInputSchema

from lemur.plugins import plugins


class AssociatedAuthoritySchema(LemurInputSchema):
    id = fields.Int()
    name = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if data.get('id'):
            return Authority.query.filter(Authority.id == data['id']).one()
        elif data.get('name'):
            return Authority.query.filter(Authority.name == data['name']).one()


class AssociatedDestinationSchema(LemurInputSchema):
    id = fields.Int(required=True)

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Destination.query.filter(Destination.id.in_(ids)).all()
        else:
            return Destination.query.filter(Destination.id == data['id']).one()


class AssociatedNotificationSchema(LemurInputSchema):
    id = fields.Int(required=True)

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Notification.query.filter(Notification.id.in_(ids)).all()
        else:
            return Notification.query.filter(Notification.id == data['id']).one()


class AssociatedCertificateSchema(LemurInputSchema):
    id = fields.Int(required=True)

    @post_load
    def get_object(self, data, many=False):
        if many:
            ids = [d['id'] for d in data]
            return Certificate.query.filter(Certificate.id.in_(ids)).all()
        else:
            return Certificate.query.filter(Certificate.id == data['id']).one()


class PluginSchema(LemurInputSchema):
    plugin_options = fields.Dict()
    slug = fields.String()

    @post_load
    def get_object(self, data, many=False):
        if many:
            return [plugins.get(plugin['slug']) for plugin in data]
        else:
            return plugins.get(data['slug'])
