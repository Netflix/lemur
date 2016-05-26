"""
.. module: lemur.endpoints.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import reqparse, Api

from lemur.common.utils import paginated_parser
from lemur.common.schema import validate_schema
from lemur.auth.service import AuthenticatedResource

from lemur.endpoints import service
from lemur.endpoints.schemas import endpoint_output_schema, endpoints_output_schema


mod = Blueprint('endpoints', __name__)
api = Api(mod)


class AuthoritiesList(AuthenticatedResource):
    """ Defines the 'endpoints' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AuthoritiesList, self).__init__()

    @validate_schema(None, endpoints_output_schema)
    def get(self):
        """
        .. http:get:: /endpoints

           The current list of endpoints

           **Example request**:

           .. sourcecode:: http

              GET /endpoints HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [
                    {
                      "id": 1,
                      "name": "endpoint1",
                      "description": "this is endpoint1",
                      "pluginName": null,
                      "chain": "-----Begin ...",
                      "body": "-----Begin ...",
                      "active": true,
                      "notBefore": "2015-06-05T17:09:39",
                      "notAfter": "2015-06-10T17:09:39"
                      "options": null
                    }
                  ]
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int default is 1
           :query filter: key value pair. format is k;v
           :query limit: limit number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

           :note: this will only show certificates that the current user is authorized to use
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)


class Authorities(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Authorities, self).__init__()

    @validate_schema(None, endpoint_output_schema)
    def get(self, endpoint_id):
        """
        .. http:get:: /endpoints/1

           One endpoint

           **Example request**:

           .. sourcecode:: http

              GET /endpoints/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "endpoint1",
                "description": "this is endpoint1",
                "pluginName": null,
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39"
                "options": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(endpoint_id)


api.add_resource(AuthoritiesList, '/endpoints', endpoint='endpoints')
api.add_resource(Authorities, '/endpoints/<int:endpoint_id>', endpoint='endpoint')
