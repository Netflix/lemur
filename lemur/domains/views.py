"""
.. module: lemur.domains.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint
from flask.ext.restful import reqparse, Api, fields

from lemur.domains import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import SensitiveDomainPermission

from lemur.common.utils import paginated_parser, marshal_items

FIELDS = {
    'id': fields.Integer,
    'name': fields.String,
    'sensitive': fields.Boolean
}

mod = Blueprint('domains', __name__)
api = Api(mod)


class DomainsList(AuthenticatedResource):
    """ Defines the 'domains' endpoint """
    def __init__(self):
        super(DomainsList, self).__init__()

    @marshal_items(FIELDS)
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @marshal_items(FIELDS)
    def post(self):
        """
        .. http:post:: /domains

           The current domain list

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

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        self.reqparse.add_argument('name', type=str, location='json')
        self.reqparse.add_argument('sensitive', type=bool, default=False, location='json')
        args = self.reqparse.parse_args()
        return service.create(args['name'], args['sensitive'])


class Domains(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Domains, self).__init__()

    @marshal_items(FIELDS)
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

    @marshal_items(FIELDS)
    def put(self, domain_id):
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
        self.reqparse.add_argument('name', type=str, location='json')
        self.reqparse.add_argument('sensitive', type=bool, default=False, location='json')
        args = self.reqparse.parse_args()

        if SensitiveDomainPermission().can():
            return service.update(domain_id, args['name'], args['sensitive'])

        return dict(message='You are not authorized to modify this domain'), 403


class CertificateDomains(AuthenticatedResource):
    """ Defines the 'domains' endpoint """
    def __init__(self):
        super(CertificateDomains, self).__init__()

    @marshal_items(FIELDS)
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['certificate_id'] = certificate_id
        return service.render(args)


api.add_resource(DomainsList, '/domains', endpoint='domains')
api.add_resource(Domains, '/domains/<int:domain_id>', endpoint='domain')
api.add_resource(CertificateDomains, '/certificates/<int:certificate_id>/domains', endpoint='certificateDomains')
