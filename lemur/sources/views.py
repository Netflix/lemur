"""
.. module: lemur.sources.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask_restful import Api, reqparse
from lemur.sources import service

from lemur.common.schema import validate_schema
from lemur.sources.schemas import (
    source_input_schema,
    source_output_schema,
    sources_output_schema,
)

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import paginated_parser


mod = Blueprint("sources", __name__)
api = Api(mod)


class SourcesList(AuthenticatedResource):
    """ Defines the 'sources' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, sources_output_schema)
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
                        "options": [
                            {
                                "name": "accountNumber",
                                "required": true,
                                "value": 111111111112,
                                "helpMessage": "Must be a valid AWS account number!",
                                "validation": "^[0-9]{12,12}$",
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
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @validate_schema(source_input_schema, source_output_schema)
    @admin_permission.require(http_exception=403)
    def post(self, data=None):
        """
        .. http:post:: /sources

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /sources HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "options": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
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
                "options": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
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
        if "plugin_options" in data["plugin"]:
            return service.create(
                data["label"],
                data["plugin"]["slug"],
                data["plugin"]["plugin_options"],
                data["description"],
            )
        else:
            return service.create(
                data["label"],
                data["plugin"]["slug"],
                data["description"],
            )


class Sources(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, source_output_schema)
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
                "options": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
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

    @validate_schema(source_input_schema, source_output_schema)
    @admin_permission.require(http_exception=403)
    def put(self, source_id, data=None):
        """
        .. http:put:: /sources/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /sources/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "options": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
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
                "options": [
                    {
                        "name": "accountNumber",
                        "required": true,
                        "value": 111111111112,
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
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
        return service.update(
            source_id,
            data["label"],
            data["plugin"]["slug"],
            data["plugin"]["plugin_options"],
            data["description"],
        )

    @admin_permission.require(http_exception=403)
    def delete(self, source_id):
        service.delete(source_id)
        return {"result": True}


class CertificateSources(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/sources'' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, sources_output_schema)
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
                        "options": [
                            {
                                "name": "accountNumber",
                                "required": true,
                                "value": 111111111112,
                                "helpMessage": "Must be a valid AWS account number!",
                                "validation": "^[0-9]{12,12}$",
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
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args["certificate_id"] = certificate_id
        return service.render(args)


api.add_resource(SourcesList, "/sources", endpoint="sources")
api.add_resource(Sources, "/sources/<int:source_id>", endpoint="account")
api.add_resource(
    CertificateSources,
    "/certificates/<int:certificate_id>/sources",
    endpoint="certificateSources",
)
