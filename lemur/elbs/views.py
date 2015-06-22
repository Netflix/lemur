"""
.. module: lemur.elbs.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint
from flask.ext.restful import reqparse, Api, fields
from lemur.elbs import service
from lemur.auth.service import AuthenticatedResource

from lemur.common.utils import marshal_items, paginated_parser


mod = Blueprint('elbs', __name__)
api = Api(mod)


FIELDS = {
    'name': fields.String,
    'id': fields.Integer,
    'region': fields.String,
    'scheme': fields.String,
    'accountId': fields.Integer(attribute='account_id'),
    'vpcId': fields.String(attribute='vpc_id')
}


class ELBsList(AuthenticatedResource):
    """ Defines the 'elbs' endpoint """
    def __init__(self):
        super(ELBsList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        parser = paginated_parser.copy()
        parser.add_argument('owner', type=str, location='args')
        parser.add_argument('id', type=str, location='args')
        parser.add_argument('accountId', type=str, dest='account_id', location='args')
        parser.add_argument('certificateId', type=str, dest='certificate_id', location='args')
        parser.add_argument('active', type=str, default='true', location='args')

        args = parser.parse_args()
        return service.render(args)


class ELBsStats(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ELBsStats, self).__init__()

    def get(self):
        self.reqparse.add_argument('metric', type=str, location='args')
        self.reqparse.add_argument('accountId', dest='account_id', location='args')
        self.reqparse.add_argument('active', type=str, default='true', location='args')

        args = self.reqparse.parse_args()

        items = service.stats(**args)
        return {"items": items, "total": len(items)}


class ELBs(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ELBs, self).__init__()

    @marshal_items(FIELDS)
    def get(self, elb_id):
        return service.get(elb_id)


api.add_resource(ELBsList, '/elbs', endpoint='elbs')
api.add_resource(ELBs, '/elbs/<int:elb_id>', endpoint='elb')
api.add_resource(ELBsStats, '/elbs/stats', endpoint='elbsStats')
