"""
.. module: lemur.logs.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask_restful import reqparse, Api

from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.auth.service import AuthenticatedResource
from lemur.logs.schemas import logs_output_schema

from lemur.logs import service


mod = Blueprint("logs", __name__)
api = Api(mod)


class LogsList(AuthenticatedResource):
    """ Defines the 'logs' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, logs_output_schema)
    def get(self):
        """
        .. http:get:: /logs

           The current log list

           **Example request**:

           .. sourcecode:: http

              GET /logs HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [
                  ]
                "total": 2
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        parser.add_argument("owner", type=str, location="args")
        parser.add_argument("id", type=str, location="args")
        args = parser.parse_args()
        return service.render(args)


api.add_resource(LogsList, "/logs", endpoint="logs")
