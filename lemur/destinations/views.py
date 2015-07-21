"""
.. module: lemur.destinations.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import Api, reqparse, fields
from lemur.destinations import service

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import paginated_parser, marshal_items

from lemur.plugins.views import FIELDS as PLUGIN_FIELDS

mod = Blueprint('destinations', __name__)
api = Api(mod)


FIELDS = {
    'description': fields.String,
    'plugin': fields.Nested(PLUGIN_FIELDS, attribute='plugin'),
    'label': fields.String,
    'id': fields.Integer,
}


class DestinationsList(AuthenticatedResource):
    """ Defines the 'destinations' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(DestinationsList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        """
        .. http:get:: /destinations

           The current account list

           **Example request**:

           .. sourcecode:: http

              GET /destinations HTTP/1.1
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
                      "id": 2,
                      "accountNumber": 222222222,
                      "label": "account2",
                      "comments": "this is a thing"
                    },
                    {
                      "id": 1,
                      "accountNumber": 11111111111,
                      "label": "account1",
                      "comments": "this is a thing"
                    },
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
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def post(self):
        """
        .. http:post:: /destinations

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /destinations HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                 "accountNumber": 11111111111,
                 "label": "account1,
                 "comments": "this is a thing"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "accountNumber": 11111111111,
                "label": "account1",
                "comments": "this is a thing"
              }

           :arg accountNumber: aws account number
           :arg label: human readable account label
           :arg comments: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('plugin', type=dict, location='json', required=True)
        self.reqparse.add_argument('description', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.create(args['label'], args['plugin']['slug'], args['plugin']['pluginOptions'], args['description'])


class Destinations(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Destinations, self).__init__()

    @marshal_items(FIELDS)
    def get(self, destination_id):
        """
        .. http:get:: /destinations/1

           Get a specific account

           **Example request**:

           .. sourcecode:: http

              GET /destinations/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "accountNumber": 11111111111,
                "label": "account1",
                "comments": "this is a thing"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(destination_id)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def put(self, destination_id):
        """
        .. http:put:: /destinations/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /destinations/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript


           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "accountNumber": 11111111111,
                "label": "labelChanged",
                "comments": "this is a thing"
              }

           :arg accountNumber: aws account number
           :arg label: human readable account label
           :arg comments: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('pluginOptions', type=dict, location='json', required=True)
        self.reqparse.add_argument('description', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.update(destination_id, args['label'], args['options'], args['description'])

    @admin_permission.require(http_exception=403)
    def delete(self, destination_id):
        service.delete(destination_id)
        return {'result': True}


class CertificateDestinations(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/destinations'' endpoint """
    def __init__(self):
        super(CertificateDestinations, self).__init__()

    @marshal_items(FIELDS)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/destinations

           The current account list for a given certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/destinations HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['certificate_id'] = certificate_id
        return service.render(args)


api.add_resource(DestinationsList, '/destinations', endpoint='destinations')
api.add_resource(Destinations, '/destinations/<int:destination_id>', endpoint='account')
api.add_resource(CertificateDestinations, '/certificates/<int:certificate_id>/destinations',
                 endpoint='certificateDestinations')
