"""
.. module: lemur.endpoints.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint, g
from flask_restful import reqparse, Api

from lemur.common.utils import paginated_parser
from lemur.common.schema import validate_schema
from lemur.auth.service import AuthenticatedResource

from lemur.endpoints import service
from lemur.endpoints.schemas import endpoint_output_schema, endpoints_output_schema


mod = Blueprint("endpoints", __name__)
api = Api(mod)


class EndpointsList(AuthenticatedResource):
    """ Defines the 'endpoints' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

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


           :query sortBy: field to sort on
           :query sortDir: asc or desc
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
        args["user"] = g.current_user
        return service.render(args)


class Endpoints(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

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


           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(endpoint_id)


api.add_resource(EndpointsList, "/endpoints", endpoint="endpoints")
api.add_resource(Endpoints, "/endpoints/<int:endpoint_id>", endpoint="endpoint")
