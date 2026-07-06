"""
.. module: lemur.destinations.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask_restful import Api, reqparse
from lemur.destinations import service

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import admin_permission
from lemur.common.utils import paginated_parser

from lemur.common.schema import validate_schema
from lemur.destinations.schemas import (
    destinations_output_schema,
    destination_input_schema,
    destination_output_schema,
)


mod = Blueprint("destinations", __name__)
api = Api(mod)


class DestinationsList(AuthenticatedResource):
    """ Defines the 'destinations' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, destinations_output_schema)
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
                "items": [{
                    "description": "test",
                    "options": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "111111111111111",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "id": 4,
                    "plugin": {
                        "pluginOptions": [{
                            "name": "accountNumber",
                            "required": true,
                            "value": "111111111111111",
                            "helpMessage": "Must be a valid AWS account number!",
                            "validation": "^[0-9]{12,12}$",
                            "type": "str"
                        }],
                        "description": "Allow the uploading of certificates to AWS IAM",
                        "slug": "aws-destination",
                        "title": "AWS"
                    },
                    "label": "test546"
                }
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int. default is 1
           :query filter: key value pair format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @validate_schema(destination_input_schema, destination_output_schema)
    @admin_permission.require(http_exception=403)
    def post(self, data=None):
        """
        .. http:post:: /destinations

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /destinations HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "description": "test33",
                "options": [{
                    "name": "accountNumber",
                    "required": true,
                    "value": "34324324",
                    "helpMessage": "Must be a valid AWS account number!",
                    "validation": "^[0-9]{12,12}$",
                    "type": "str"
                }],
                "id": 4,
                "plugin": {
                    "pluginOptions": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "34324324",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "description": "Allow the uploading of certificates to AWS IAM",
                    "slug": "aws-destination",
                    "title": "AWS"
                },
                "label": "test546"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "description": "test33",
                "options": [{
                    "name": "accountNumber",
                    "required": true,
                    "value": "34324324",
                    "helpMessage": "Must be a valid AWS account number!",
                    "validation": "^[0-9]{12,12}$",
                    "type": "str"
                }],
                "id": 4,
                "plugin": {
                    "pluginOptions": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "111111111111111",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "description": "Allow the uploading of certificates to AWS IAM",
                    "slug": "aws-destination",
                    "title": "AWS"
                },
                "label": "test546"
              }

           :arg label: human readable account label
           :arg description: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.create(
            data["label"],
            data["plugin"]["slug"],
            data["plugin"]["plugin_options"],
            data["description"],
        )


class Destinations(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, destination_output_schema)
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
                "description": "test",
                "options": [{
                    "name": "accountNumber",
                    "required": true,
                    "value": "111111111111111",
                    "helpMessage": "Must be a valid AWS account number!",
                    "validation": "^[0-9]{12,12}$",
                    "type": "str"
                }],
                "id": 4,
                "plugin": {
                    "pluginOptions": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "111111111111111",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "description": "Allow the uploading of certificates to AWS IAM",
                    "slug": "aws-destination",
                    "title": "AWS"
                },
                "label": "test546"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(destination_id)

    @validate_schema(destination_input_schema, destination_output_schema)
    @admin_permission.require(http_exception=403)
    def put(self, destination_id, data=None):
        """
        .. http:put:: /destinations/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /destinations/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8


              {
                "description": "test33",
                "options": [{
                    "name": "accountNumber",
                    "required": true,
                    "value": "34324324",
                    "helpMessage": "Must be a valid AWS account number!",
                    "validation": "^[0-9]{12,12}$",
                    "type": "str"
                }],
                "id": 4,
                "plugin": {
                    "pluginOptions": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "34324324",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "description": "Allow the uploading of certificates to AWS IAM",
                    "slug": "aws-destination",
                    "title": "AWS"
                },
                "label": "test546"
              }


           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "description": "test",
                "options": [{
                    "name": "accountNumber",
                    "required": true,
                    "value": "111111111111111",
                    "helpMessage": "Must be a valid AWS account number!",
                    "validation": "^[0-9]{12,12}$",
                    "type": "str"
                }],
                "id": 4,
                "plugin": {
                    "pluginOptions": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "111111111111111",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "description": "Allow the uploading of certificates to AWS IAM",
                    "slug": "aws-destination",
                    "title": "AWS"
                },
                "label": "test546"
              }

           :arg accountNumber: aws account number
           :arg label: human readable account label
           :arg description: some description about the account
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.update(
            destination_id,
            data["label"],
            data["plugin"]["slug"],
            data["plugin"]["plugin_options"],
            data["description"],
        )

    @admin_permission.require(http_exception=403)
    def delete(self, destination_id):
        service.delete(destination_id)
        return {"result": True}


class CertificateDestinations(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/destinations'' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, destination_output_schema)
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

              {
                "items": [{
                    "description": "test",
                    "options": [{
                        "name": "accountNumber",
                        "required": true,
                        "value": "111111111111111",
                        "helpMessage": "Must be a valid AWS account number!",
                        "validation": "^[0-9]{12,12}$",
                        "type": "str"
                    }],
                    "id": 4,
                    "plugin": {
                        "pluginOptions": [{
                            "name": "accountNumber",
                            "required": true,
                            "value": "111111111111111",
                            "helpMessage": "Must be a valid AWS account number!",
                            "validation": "^[0-9]{12,12}$",
                            "type": "str"
                        }],
                        "description": "Allow the uploading of certificates to AWS IAM",
                        "slug": "aws-destination",
                        "title": "AWS"
                    },
                    "label": "test546"
                }
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


class DestinationsStats(AuthenticatedResource):
    """ Defines the 'destinations' stats endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def get(self):
        self.reqparse.add_argument("metric", type=str, location="args")
        args = self.reqparse.parse_args()
        items = service.stats(**args)
        return dict(items=items, total=len(items))


api.add_resource(DestinationsList, "/destinations", endpoint="destinations")
api.add_resource(
    Destinations, "/destinations/<int:destination_id>", endpoint="destination"
)
api.add_resource(
    CertificateDestinations,
    "/certificates/<int:certificate_id>/destinations",
    endpoint="certificateDestinations",
)
api.add_resource(DestinationsStats, "/destinations/stats", endpoint="destinationStats")
