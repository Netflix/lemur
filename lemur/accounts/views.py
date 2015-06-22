"""
.. module: lemur.accounts.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import Api, reqparse, fields
from lemur.accounts import service

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import paginated_parser, marshal_items


mod = Blueprint('accounts', __name__)
api = Api(mod)


FIELDS = {
    'accountNumber': fields.Integer(attribute='account_number'),
    'label': fields.String,
    'comments': fields.String(attribute='notes'),
    'id': fields.Integer,
}


class AccountsList(AuthenticatedResource):
    """ Defines the 'accounts' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AccountsList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        """
        .. http:get:: /accounts

           The current account list

           **Example request**:

           .. sourcecode:: http

              GET /accounts HTTP/1.1
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
        .. http:post:: /accounts

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /accounts HTTP/1.1
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
        self.reqparse.add_argument('accountNumber', type=int, dest="account_number", location='json', required=True)
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('comments', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.create(args['account_number'], args['label'], args['comments'])


class Accounts(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Accounts, self).__init__()

    @marshal_items(FIELDS)
    def get(self, account_id):
        """
        .. http:get:: /accounts/1

           Get a specific account

           **Example request**:

           .. sourcecode:: http

              GET /accounts/1 HTTP/1.1
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
        return service.get(account_id)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def put(self, account_id):
        """
        .. http:post:: /accounts/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /accounts/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                 "accountNumber": 11111111111,
                 "label": "labelChanged,
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
                "label": "labelChanged",
                "comments": "this is a thing"
              }

           :arg accountNumber: aws account number
           :arg label: human readable account label
           :arg comments: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument('accountNumber', type=int, dest="account_number", location='json', required=True)
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('comments', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.update(account_id, args['account_number'], args['label'], args['comments'])

    @admin_permission.require(http_exception=403)
    def delete(self, account_id):
        service.delete(account_id)
        return {'result': True}



class CertificateAccounts(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/accounts'' endpoint """
    def __init__(self):
        super(CertificateAccounts, self).__init__()

    @marshal_items(FIELDS)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/accounts

           The current account list for a given certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/accounts HTTP/1.1
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
        args['certificate_id'] = certificate_id
        return service.render(args)


api.add_resource(AccountsList, '/accounts', endpoint='accounts')
api.add_resource(Accounts, '/accounts/<int:account_id>', endpoint='account')
api.add_resource(CertificateAccounts, '/certificates/<int:certificate_id>/accounts', endpoint='certificateAccounts')

