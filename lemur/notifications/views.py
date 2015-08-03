"""
.. module: lemur.notifications.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import Api, reqparse, fields
from lemur.notifications import service

from lemur.auth.service import AuthenticatedResource
from lemur.common.utils import paginated_parser, marshal_items


mod = Blueprint('notifications', __name__)
api = Api(mod)


FIELDS = {
    'description': fields.String,
    'notificationOptions': fields.Raw(attribute='options'),
    'pluginName': fields.String(attribute='plugin_name'),
    'label': fields.String,
    'active': fields.Boolean,
    'id': fields.Integer,
}


class NotificationsList(AuthenticatedResource):
    """ Defines the 'notifications' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(NotificationsList, self).__init__()

    @marshal_items(FIELDS)
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
                        "notificationOptions": [
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
                                "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        parser.add_argument('active', type=bool, location='args')
        args = parser.parse_args()
        return service.render(args)

    @marshal_items(FIELDS)
    def post(self):
        """
        .. http:post:: /notifications

           Creates a new account

           **Example request**:

           .. sourcecode:: http

              POST /notifications HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "description": "a test",
                "notificationOptions": [
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
                        "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
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
                "notificationOptions": [
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
                        "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
                        "type": "str"
                    }
                ],
                "label": "test",
                "pluginName": "email-notification",
                "active": true,
                "id": 2
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
        self.reqparse.add_argument('certificates', type=list, default=[], location='json')

        args = self.reqparse.parse_args()
        return service.create(
            args['label'],
            args['plugin']['slug'],
            args['plugin']['pluginOptions'],
            args['description'],
            args['certificates']
        )


class Notifications(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Notifications, self).__init__()

    @marshal_items(FIELDS)
    def get(self, notification_id):
        """
        .. http:get:: /notifications/1

           Get a specific account

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
                "notificationOptions": [
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
                        "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
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

    @marshal_items(FIELDS)
    def put(self, notification_id):
        """
        .. http:put:: /notifications/1

           Updates an account

           **Example request**:

           .. sourcecode:: http

              POST /notifications/1 HTTP/1.1
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
        self.reqparse.add_argument('plugin', type=dict, location='json', required=True)
        self.reqparse.add_argument('active', type=bool, location='json')
        self.reqparse.add_argument('certificates', type=list, default=[], location='json')
        self.reqparse.add_argument('description', type=str, location='json')

        args = self.reqparse.parse_args()
        return service.update(
            notification_id,
            args['label'],
            args['plugin']['pluginOptions'],
            args['description'],
            args['active'],
            args['certificates']
        )

    def delete(self, notification_id):
        service.delete(notification_id)
        return {'result': True}


class CertificateNotifications(AuthenticatedResource):
    """ Defines the 'certificate/<int:certificate_id/notifications'' endpoint """
    def __init__(self):
        super(CertificateNotifications, self).__init__()

    @marshal_items(FIELDS)
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
                        "notificationOptions": [
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
                                "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        parser.add_argument('active', type=bool, location='args')
        args = parser.parse_args()
        args['certificate_id'] = certificate_id
        return service.render(args)


api.add_resource(NotificationsList, '/notifications', endpoint='notifications')
api.add_resource(Notifications, '/notifications/<int:notification_id>', endpoint='notification')
api.add_resource(CertificateNotifications, '/certificates/<int:certificate_id>/notifications',
                 endpoint='certificateNotifications')
