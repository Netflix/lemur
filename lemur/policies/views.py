from flask import Blueprint
from flask_restful import reqparse, Api

from lemur.policies import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import SensitiveDomainPermission

from lemur.common.schema import validate_schema, decorator_error_handling
from lemur.common.utils import paginated_parser

from lemur.policies.schemas import (
    police_input_schema,
    police_output_schema,
    polices_output_schema
)

mod = Blueprint("polices", __name__)
api = Api(mod)


class PolicesList(AuthenticatedResource):
    """ Defines the 'domains' endpoint """

    def __init__(self):
        super(PolicesList, self).__init__()

    @validate_schema(None, polices_output_schema)
    def get(self):
        """
        .. http:get:: /polices
           The current polices list
           **Example request**:
           .. sourcecode:: http
              GET /polices HTTP/1.1
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
                      "name": "example",
                      "days": 10
                    },
                    {
                      "id": 2,
                      "name": "example2",
                      "days": 20
                    }
                  ]
                "total": 2
              }
           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query count: count number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @validate_schema(police_input_schema, police_output_schema)
    def post(self, data=None):
        print(data["name"], data["days"])
        """
        .. http:post:: /polices
           The current police list
           **Example request**:
           .. sourcecode:: http
              GET /polices HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              {
                "name": "example",
                "days": 10
              }
           **Example response**:
           .. sourcecode:: http
              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript
              {
                "id": 1,
                "name": "example",
                "days": 10
              }
           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.create(name=data["name"], days=data["days"])


class Police(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Police, self).__init__()

    @validate_schema(None, police_output_schema)
    def get(self, police_id):
        """
        .. http:get:: /polices/1
           Get a police
           **Example request**:
           .. sourcecode:: http
              GET /polices/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
           **Example response**:
           .. sourcecode:: http
              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript
              {
                "name": "example",
                "id": 3,
                "days": 10
              }
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(police_id)

    @validate_schema(police_input_schema, police_output_schema)
    def put(self, police_id, data=None):
        """
        .. http:put:: /polices/1
           Updates an police
           **Example request**:
           .. sourcecode:: http
              POST /polices/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              {
                "name": "example",
                "id": 3,
                "days": 10
              }
           **Example response**:
           .. sourcecode:: http
              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript
              {
                "name": "example",
                "id": 3,
                "days": 10
              }
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.update(
            police_id,
            name=data["name"],
            days=data["days"],
        )

    @decorator_error_handling
    def delete(self, police_id):
        service.delete(police_id)
        return {"result": True}


api.add_resource(PolicesList, "/polices", endpoint="polices")
api.add_resource(Police, "/polices/<int:police_id>", endpoint="police")