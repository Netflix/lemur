"""
.. module: lemur.domains.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint
from flask_restful import reqparse, Api

from lemur.domains import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import SensitiveDomainPermission, StrictRolePermission

from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.domains.schemas import (
    domain_input_schema,
    domain_output_schema,
    domains_output_schema,
)

mod = Blueprint("domains", __name__)
api = Api(mod)


class DomainsList(AuthenticatedResource):
    """ Defines the 'domains' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, domains_output_schema)
    def get(self):
        """
        .. http:get:: /domains

           The current domain list

           **Example request**:

           .. sourcecode:: http

              GET /domains HTTP/1.1
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
                      "name": "www.example.com",
                      "sensitive": false
                    },
                    {
                      "id": 2,
                      "name": "www.example2.com",
                      "sensitive": false
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

    @validate_schema(domain_input_schema, domain_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /domains

           The current domain list

           **Example request**:

           .. sourcecode:: http

              POST /domains HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "name": "www.example.com",
                "sensitive": false
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "www.example.com",
                "sensitive": false
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
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to create a domain"), 403
        return service.create(data["name"], data["sensitive"])


class Domains(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, domain_output_schema)
    def get(self, domain_id):
        """
        .. http:get:: /domains/1

           Fetch one domain

           **Example request**:

           .. sourcecode:: http

              GET /domains HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "name": "www.example.com",
                  "sensitive": false
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(domain_id)

    @validate_schema(domain_input_schema, domain_output_schema)
    def put(self, domain_id, data=None):
        """
        .. http:get:: /domains/1

           update one domain

           **Example request**:

           .. sourcecode:: http

              GET /domains HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                  "name": "www.example.com",
                  "sensitive": false
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "name": "www.example.com",
                  "sensitive": false
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if not StrictRolePermission().can() or not SensitiveDomainPermission().can():
            return dict(message="You are not authorized to modify this domain."), 403
        return service.update(domain_id, data["name"], data["sensitive"])


class CertificateDomains(AuthenticatedResource):
    """ Defines the 'domains' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, domains_output_schema)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/domains

           The current domain list

           **Example request**:

           .. sourcecode:: http

              GET /domains HTTP/1.1
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
                      "name": "www.example.com",
                      "sensitive": false
                    },
                    {
                      "id": 2,
                      "name": "www.example2.com",
                      "sensitive": false
                    }
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
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args["certificate_id"] = certificate_id
        return service.render(args)


api.add_resource(DomainsList, "/domains", endpoint="domains")
api.add_resource(Domains, "/domains/<int:domain_id>", endpoint="domain")
api.add_resource(
    CertificateDomains,
    "/certificates/<int:certificate_id>/domains",
    endpoint="certificateDomains",
)
