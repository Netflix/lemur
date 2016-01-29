"""
.. module: lemur.sources.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import Api, reqparse, fields
from lemur.sources import service

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import paginated_parser, marshal_items


mod = Blueprint('sources', __name__)
api = Api(mod)


FIELDS = {
    'description': fields.String,
    'sourceOptions': fields.Raw(attribute='options'),
    'pluginName': fields.String(attribute='plugin_name'),
    'lastRun': fields.DateTime(attribute='last_run', dt_format='iso8061'),
    'label': fields.String,
    'id': fields.Integer,
}


class SourcesList(AuthenticatedResource):
    """ Defines the 'sources' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(SourcesList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        """
        .. http:get:: /sources

           The current account list

           **Example request**:

           .. sourcecode:: http

              GET /sources HTTP/1.1
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
                        "sourceOptions": [
                            {
                                "name": "accountNumber",
                                "required": true,
                                "value": 111111111112,
                                "helpMessage": "Must be a valid AWS account number!",
                                "validation": "/^[0-9]{12,12}$/",
                                "type": "int"
                            }
                        ],
                        "pluginName": "aws-source",
                        "lastRun": "2015-08-01T15:40:58",
                        "id": 3,
                        "description": "test",
                        "label": "test"
                    }
                ],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query limit: limit number default is 10
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
        .. http:post:: /sources

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /sources HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "sourceOptions": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "/^[0-9]{12,12}$/",
                        "type": "int"
                    }
                ],
                "pluginName": "aws-source",
                "id": 3,
                "lastRun": "2015-08-01T15:40:58",
                "description": "test",
                "label": "test"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "sourceOptions": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "/^[0-9]{12,12}$/",
                        "type": "int"
                    }
                ],
                "pluginName": "aws-source",
                "id": 3,
                "lastRun": "2015-08-01T15:40:58",
                "description": "test",
                "label": "test"
              }

           :arg label: human readable account label
           :arg description: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('plugin', type=dict, location='json', required=True)
        self.reqparse.add_argument('description', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.create(args['label'], args['plugin']['slug'], args['plugin']['pluginOptions'], args['description'])


class Sources(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Sources, self).__init__()

    @marshal_items(FIELDS)
    def get(self, source_id):
        """
        .. http:get:: /sources/1

           Get a specific account

           **Example request**:

           .. sourcecode:: http

              GET /sources/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "sourceOptions": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "/^[0-9]{12,12}$/",
                        "type": "int"
                    }
                ],
                "pluginName": "aws-source",
                "id": 3,
                "lastRun": "2015-08-01T15:40:58",
                "description": "test",
                "label": "test"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(source_id)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def put(self, source_id):
        """
        .. http:put:: /sources/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /sources/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "sourceOptions": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "/^[0-9]{12,12}$/",
                        "type": "int"
                    }
                ],
                "pluginName": "aws-source",
                "id": 3,
                "lastRun": "2015-08-01T15:40:58",
                "description": "test",
                "label": "test"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "sourceOptions": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "/^[0-9]{12,12}$/",
                        "type": "int"
                    }
                ],
                "pluginName": "aws-source",
                "id": 3,
                "lastRun": "2015-08-01T15:40:58",
                "description": "test",
                "label": "test"
              }

           :arg accountNumber: aws account number
           :arg label: human readable account label
           :arg description: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument('label', type=str, location='json', required=True)
        self.reqparse.add_argument('plugin', type=dict, location='json', required=True)
        self.reqparse.add_argument('description', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.update(source_id, args['label'], args['plugin']['pluginOptions'], args['description'])

    @admin_permission.require(http_exception=403)
    def delete(self, source_id):
        service.delete(source_id)
        return {'result': True}


class CertificateSources(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/sources'' endpoint """
    def __init__(self):
        super(CertificateSources, self).__init__()

    @marshal_items(FIELDS)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/sources

           The current account list for a given certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/sources HTTP/1.1
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
                        "sourceOptions": [
                            {
                                "name": "accountNumber",
                                "required": true,
                                "value": 111111111112,
                                "helpMessage": "Must be a valid AWS account number!",
                                "validation": "/^[0-9]{12,12}$/",
                                "type": "int"
                            }
                        ],
                        "pluginName": "aws-source",
                        "id": 3,
                        "lastRun": "2015-08-01T15:40:58",
                        "description": "test",
                        "label": "test"
                    }
                ],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query limit: limit number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['certificate_id'] = certificate_id
        return service.render(args)


api.add_resource(SourcesList, '/sources', endpoint='sources')
api.add_resource(Sources, '/sources/<int:source_id>', endpoint='account')
api.add_resource(CertificateSources, '/certificates/<int:certificate_id>/sources',
                 endpoint='certificateSources')
