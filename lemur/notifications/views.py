"""
.. module: lemur.notifications.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask_restful import Api, reqparse, inputs
from lemur.notifications import service
from lemur.notifications.schemas import (
    notification_input_schema,
    notification_output_schema,
    notifications_output_schema,
)

from lemur.auth.service import AuthenticatedResource
from lemur.common.utils import paginated_parser
from lemur.auth.permissions import StrictRolePermission

from lemur.common.schema import validate_schema


mod = Blueprint("notifications", __name__)
api = Api(mod)


class NotificationsList(AuthenticatedResource):
    """ Defines the 'notifications' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, notifications_output_schema)
    def get(self):
        """
        .. http:get:: /notifications

           The current account list

           **Example request**:

           .. sourcecode:: http

              GET /notifications HTTP/1.1
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
                        "description": "An example",
                        "options": [
                            {
                                "name": "interval",
                                "required": true,
                                "value": 5,
                                "helpMessage": "Number of days to be alert before expiration.",
                                "validation": "^\\d+$",
                                "type": "int"
                            },
                            {
                                "available": [
                                    "days",
                                    "weeks",
                                    "months"
                                ],
                                "name": "unit",
                                "required": true,
                                "value": "weeks",
                                "helpMessage": "Interval unit",
                                "validation": "",
                                "type": "select"
                            },
                            {
                                "name": "recipients",
                                "required": true,
                                "value": "kglisson@netflix.com,example@netflix.com",
                                "helpMessage": "Comma delimited list of email addresses",
                                "validation": "^([\\w+-.%]+@[-\\w.]+\\.[A-Za-z]{2,4},?)+$",
                                "type": "str"
                            }
                        ],
                        "label": "example",
                        "pluginName": "email-notification",
                        "active": true,
                        "id": 2
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
        parser.add_argument("active", type=inputs.boolean, location="args")
        args = parser.parse_args()
        return service.render(args)

    @validate_schema(notification_input_schema, notification_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /notifications

           Creates a new notification

           **Example request**:

           .. sourcecode:: http

              POST /notifications HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "description": "a test",
                "options": [
                    {
                        "name": "interval",
                        "required": true,
                        "value": 5,
                        "helpMessage": "Number of days to be alert before expiration.",
                        "validation": "^\\d+$",
                        "type": "int"
                    },
                    {
                        "available": [
                            "days",
                            "weeks",
                            "months"
                        ],
                        "name": "unit",
                        "required": true,
                        "value": "weeks",
                        "helpMessage": "Interval unit",
                        "validation": "",
                        "type": "select"
                    },
                    {
                        "name": "recipients",
                        "required": true,
                        "value": "kglisson@netflix.com,example@netflix.com",
                        "helpMessage": "Comma delimited list of email addresses",
                        "validation": "^([\\w+-.%]+@[-\\w.]+\\.[A-Za-z]{2,4},?)+$",
                        "type": "str"
                    }
                ],
                "label": "test",
                "pluginName": "email-notification",
                "active": true,
                "id": 2
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "description": "a test",
                "options": [
                    {
                        "name": "interval",
                        "required": true,
                        "value": 5,
                        "helpMessage": "Number of days to be alert before expiration.",
                        "validation": "^\\d+$",
                        "type": "int"
                    },
                    {
                        "available": [
                            "days",
                            "weeks",
                            "months"
                        ],
                        "name": "unit",
                        "required": true,
                        "value": "weeks",
                        "helpMessage": "Interval unit",
                        "validation": "",
                        "type": "select"
                    },
                    {
                        "name": "recipients",
                        "required": true,
                        "value": "kglisson@netflix.com,example@netflix.com",
                        "helpMessage": "Comma delimited list of email addresses",
                        "validation": "^([\\w+-.%]+@[-\\w.]+\\.[A-Za-z]{2,4},?)+$",
                        "type": "str"
                    }
                ],
                "label": "test",
                "pluginName": "email-notification",
                "active": true,
                "id": 2
              }

           :label label: notification name
           :label slug: notification plugin slug
           :label plugin_options: notification plugin options
           :label description: notification description
           :label active: whether or not the notification is active/enabled
           :label certificates: certificates to attach to notification
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to create a new notification."), 403
        return service.create(
            data["label"],
            data["plugin"]["slug"],
            data["plugin"]["plugin_options"],
            data["description"],
            data["certificates"],
        )


class Notifications(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, notification_output_schema)
    def get(self, notification_id):
        """
        .. http:get:: /notifications/1

           Get a specific notification

           **Example request**:

           .. sourcecode:: http

              GET /notifications/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "description": "a test",
                "options": [
                    {
                        "name": "interval",
                        "required": true,
                        "value": 5,
                        "helpMessage": "Number of days to be alert before expiration.",
                        "validation": "^\\d+$",
                        "type": "int"
                    },
                    {
                        "available": [
                            "days",
                            "weeks",
                            "months"
                        ],
                        "name": "unit",
                        "required": true,
                        "value": "weeks",
                        "helpMessage": "Interval unit",
                        "validation": "",
                        "type": "select"
                    },
                    {
                        "name": "recipients",
                        "required": true,
                        "value": "kglisson@netflix.com,example@netflix.com",
                        "helpMessage": "Comma delimited list of email addresses",
                        "validation": "^([\\w+-.%]+@[-\\w.]+\\.[A-Za-z]{2,4},?)+$",
                        "type": "str"
                    }
                ],
                "label": "test",
                "pluginName": "email-notification",
                "active": true,
                "id": 2
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(notification_id)

    @validate_schema(notification_input_schema, notification_output_schema)
    def put(self, notification_id, data=None):
        """
        .. http:put:: /notifications/1

           Updates a notification

           **Example request**:

           .. sourcecode:: http

              PUT /notifications/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "label": "labelChanged",
                "plugin": {
                    "slug": "email-notification",
                    "plugin_options": "???"
                  },
                "description": "Sample notification",
                "active": "true",
                "added_certificates": "???",
                "removed_certificates": "???"
              }


           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "label": "labelChanged",
                "plugin": {
                    "slug": "email-notification",
                    "plugin_options": "???"
                  },
                "description": "Sample notification",
                "active": "true",
                "added_certificates": "???",
                "removed_certificates": "???"
              }

           :label label: notification name
           :label slug: notification plugin slug
           :label plugin_options: notification plugin options
           :label description: notification description
           :label active: whether or not the notification is active/enabled
           :label added_certificates: certificates to add
           :label removed_certificates: certificates to remove
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to update a notification."), 403
        return service.update(
            notification_id,
            data["label"],
            data["plugin"]["slug"],
            data["plugin"]["plugin_options"],
            data["description"],
            data["active"],
            data["added_certificates"],
            data["removed_certificates"],
        )

    def delete(self, notification_id):
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to delete a notification."), 403
        service.delete(notification_id)
        return {"result": True}


class CertificateNotifications(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/notifications'' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, notifications_output_schema)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/notifications

           The current account list for a given certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/notifications HTTP/1.1
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
                        "description": "An example",
                        "options": [
                            {
                                "name": "interval",
                                "required": true,
                                "value": 555,
                                "helpMessage": "Number of days to be alert before expiration.",
                                "validation": "^\\d+$",
                                "type": "int"
                            },
                            {
                                "available": [
                                    "days",
                                    "weeks",
                                    "months"
                                ],
                                "name": "unit",
                                "required": true,
                                "value": "weeks",
                                "helpMessage": "Interval unit",
                                "validation": "",
                                "type": "select"
                            },
                            {
                                "name": "recipients",
                                "required": true,
                                "value": "kglisson@netflix.com,example@netflix.com",
                                "helpMessage": "Comma delimited list of email addresses",
                                "validation": "^([\\w+-.%]+@[-\\w.]+\\.[A-Za-z]{2,4},?)+$",
                                "type": "str"
                            }
                        ],
                        "label": "example",
                        "pluginName": "email-notification",
                        "active": true,
                        "id": 2
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
        return service.render({"certificate_id": certificate_id})


api.add_resource(NotificationsList, "/notifications", endpoint="notifications")
api.add_resource(
    Notifications, "/notifications/<int:notification_id>", endpoint="notification"
)
api.add_resource(
    CertificateNotifications,
    "/certificates/<int:certificate_id>/notifications",
    endpoint="certificateNotifications",
)
