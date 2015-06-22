"""
.. module: lemur.listeners.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint
from flask.ext.restful import reqparse, Api, fields

from lemur.listeners import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import marshal_items, paginated_parser


mod = Blueprint('listeners', __name__)
api = Api(mod)


FIELDS = {
    'id': fields.Integer,
    'elbId': fields.Integer(attribute="elb_id"),
    'certificateId': fields.Integer(attribute="certificate_id"),
    'instancePort': fields.Integer(attribute="instance_port"),
    'instanceProtocol': fields.String(attribute="instance_protocol"),
    'loadBalancerPort': fields.Integer(attribute="load_balancer_port"),
    'loadBalancerProtocol': fields.String(attribute="load_balancer_protocol")
}


class ListenersList(AuthenticatedResource):
    def __init__(self):
        super(ListenersList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        parser = paginated_parser.copy()
        parser.add_argument('certificateId', type=int, dest='certificate_id', location='args')
        args = parser.parse_args()
        return service.render(args)


class ListenersCertificateList(AuthenticatedResource):
    def __init__(self):
        super(ListenersCertificateList, self).__init__()

    @marshal_items(FIELDS)
    def get(self, certificate_id):
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['certificate_id'] = certificate_id
        return service.render(args)


class ListenersELBList(AuthenticatedResource):
    def __init__(self):
        super(ListenersELBList, self).__init__()

    @marshal_items(FIELDS)
    def get(self, elb_id):
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['elb_id'] = elb_id
        return service.render(args)


class ListenersStats(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ListenersStats, self).__init__()

    def get(self):
        self.reqparse.add_argument('metric', type=str, location='args')
        self.reqparse.add_argument('accountId', dest='account_id', location='args')
        self.reqparse.add_argument('active', type=str, default='true', location='args')

        args = self.reqparse.parse_args()

        items = service.stats(**args)
        return {"items": items, "total": len(items)}


class Listeners(AuthenticatedResource):
    def __init__(self):
        super(Listeners, self).__init__()

    @marshal_items(FIELDS)
    def get(self, listener_id):
        return service.get(listener_id)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def post(self):
        self.reqparse.add_argument('elbId', type=str, dest='elb_id', required=True, location='json')
        self.reqparse.add_argument('instanceProtocol', type=str, dest='instance_protocol', required=True, location='json')
        self.reqparse.add_argument('instancePort', type=int, dest='instance_port', required=True, location='json')
        self.reqparse.add_argument('loadBalancerProtocol', type=str, dest='load_balancer_protocol', required=True, location='json')
        self.reqparse.add_argument('loadBalancerPort', type=int, dest='load_balancer_port', required=True, location='json')
        self.reqparse.add_argument('certificateId', type=int, dest='certificate_id', location='json')

        args = self.reqparse.parse_args()
        return service.create(**args)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def put(self, listener_id):
        self.reqparse.add_argument('instanceProtocol', type=str, dest='instance_protocol', required=True, location='json')
        self.reqparse.add_argument('instancePort', type=int, dest='instance_port', required=True, location='json')
        self.reqparse.add_argument('loadBalancerProtocol', type=str, dest='load_balancer_protocol', required=True, location='json')
        self.reqparse.add_argument('loadBalancerPort', type=int, dest='load_balancer_port', required=True, location='json')
        self.reqparse.add_argument('certificateId', type=int, dest='certificate_id', location='json')

        args = self.reqparse.parse_args()
        return service.update(listener_id, **args)

    @admin_permission.require(http_exception=403)
    def delete(self, listener_id):
        return service.delete(listener_id)


api.add_resource(ListenersList, '/listeners', endpoint='listeners')
api.add_resource(Listeners, '/listeners/<int:listener_id>', endpoint='listener')
api.add_resource(ListenersStats, '/listeners/stats', endpoint='listenersStats')
api.add_resource(ListenersCertificateList, '/certificates/<int:certificate_id>/listeners', endpoint='listenersCertificates')
api.add_resource(ListenersELBList, '/elbs/<int:elb_id>/listeners', endpoint='elbListeners')
