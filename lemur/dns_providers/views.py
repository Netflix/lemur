"""
.. module: lemur.dns)providers.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
"""
from flask import Blueprint, g
from flask_restful import reqparse, Api

from lemur.auth.permissions import admin_permission
from lemur.auth.service import AuthenticatedResource
from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser
from lemur.dns_providers import service
from lemur.dns_providers.schemas import dns_provider_schema

mod = Blueprint('dns_providers', __name__)
api = Api(mod)


class DnsProvidersList(AuthenticatedResource):
    """ Defines the 'dns_providers' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(DnsProvidersList, self).__init__()

    @validate_schema(None, dns_provider_schema)
    def get(self):
        """
        .. http:get:: /dns_providers

           The current list of DNS Providers

           **Example request**:

           .. sourcecode:: http

              GET /dns_providers HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "id": 1,
                    "name": "test",
                    "description": "test",
                    "provider_type": "dyn",
                    "status": "active",
                }],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int. default is 1
           :query filter: key value pair format is k;v
           :query count: count number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        parser = paginated_parser.copy()
        parser.add_argument('id', type=int, location='args')
        parser.add_argument('name', type=str, location='args')
        parser.add_argument('type', type=str, location='args')

        args = parser.parse_args()
        args['user'] = g.user
        return service.render(args)

    @admin_permission.require(http_exception=403)
    def delete(self, dns_provider_id):
        service.delete(dns_provider_id)
        return {'result': True}


class DnsProviderTypes(AuthenticatedResource):
    """ Defines the 'dns_provider_types' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(DnsProviderTypes, self).__init__()

    def get(self):
        return service.get_types()


api.add_resource(DnsProvidersList, '/dns_providers', endpoint='dns_providers')
api.add_resource(DnsProvidersList, '/dns_providers/<int:dns_provider_id>', endpoint='dns_provider')
api.add_resource(DnsProviderTypes, '/dns_provider_types', endpoint='dns_provider_types')
