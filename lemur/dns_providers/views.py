"""
.. module: lemur.dns)providers.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
"""
from flask import Blueprint
from flask_restful import reqparse, Api


from lemur.auth.service import AuthenticatedResource

from lemur.dns_providers import service

mod = Blueprint('dns_providers', __name__)
api = Api(mod)


class DnsProvidersList(AuthenticatedResource):
    """ Defines the 'dns_providers' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(DnsProvidersList, self).__init__()

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
        return service.get_all_dns_providers()


api.add_resource(DnsProvidersList, '/dns_providers', endpoint='dns_providers')
