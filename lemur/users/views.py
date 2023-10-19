"""
.. module: lemur.users.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import g, Blueprint
from flask_restful import reqparse, Api

from lemur.auth.permissions import admin_permission
from lemur.auth.service import AuthenticatedResource
from lemur.certificates import service as certificate_service
from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser
from lemur.roles import service as role_service
from lemur.users import service
from lemur.users.schemas import (
    user_input_schema,
    user_output_schema,
    users_output_schema, user_create_input_schema,
)

mod = Blueprint("users", __name__)
api = Api(mod)


class UsersList(AuthenticatedResource):
    """ Defines the 'users' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, users_output_schema)
    def get(self):
        """
        .. http:get:: /users

           The current user list

           **Example request**:

           .. sourcecode:: http

              GET /users HTTP/1.1
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
                       "active": True,
                       "email": "user2@example.com",
                       "username": "user2",
                       "profileImage": null
                    },
                    {
                       "id": 1,
                       "active": False,
                       "email": "user1@example.com",
                       "username": "user1",
                       "profileImage": null
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
        """
        parser = paginated_parser.copy()
        parser.add_argument("owner", type=str, location="args")
        parser.add_argument("id", type=str, location="args")
        args = parser.parse_args()
        return service.render(args)

    @validate_schema(user_create_input_schema, user_output_schema)
    @admin_permission.require(http_exception=403)
    def post(self, data=None):
        """
        .. http:post:: /users

           Creates a new user

           **Example request with ID**:

           .. sourcecode:: http

              POST /users HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "username": "user3",
                 "email": "user3@example.com",
                 "active": true,
                 "roles": [
                    {"id": 1}
                 ]
              }

           **Example request with name**:

           .. sourcecode:: http

              POST /users HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "username": "user3",
                 "email": "user3@example.com",
                 "active": true,
                 "roles": [
                    {"name": "myRole"}
                 ]
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 3,
                  "active": True,
                  "email": "user3@example.com",
                  "username": "user3",
                  "profileImage": null
              }

           :arg username: username for new user
           :arg email: email address for new user
           :arg password: password for new user
           :arg active: boolean, if the user is currently active
           :arg roles: list, roles that the user should be apart of
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.create(
            data["username"],
            data["password"],
            data["email"],
            data["active"],
            None,
            data["roles"],
        )


class Users(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, user_output_schema)
    def get(self, user_id):
        """
        .. http:get:: /users/1

           Get a specific user

           **Example request**:

           .. sourcecode:: http

              GET /users/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "active": false,
                  "email": "user1@example.com",
                  "username": "user1",
                  "profileImage": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.get(user_id)

    @validate_schema(user_input_schema, user_output_schema)
    @admin_permission.require(http_exception=403)
    def put(self, user_id, data=None):
        """
        .. http:put:: /users/1

           Update a user

           **Example request with ID**:

           .. sourcecode:: http

              PUT /users/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "username": "user1",
                 "email": "user1@example.com",
                 "active": false,
                 "roles": [
                     {"id": 1}
                 ]
              }

           **Example request with name**:

           .. sourcecode:: http

              PUT /users/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "username": "user1",
                 "email": "user1@example.com",
                 "active": false,
                 "roles": [
                     {"name": "myRole"}
                 ]
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "id": 1,
                 "username": "user1",
                 "email": "user1@example.com",
                 "active": false,
                 "profileImage": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return service.update(
            user_id,
            data["username"],
            data["email"],
            data["active"],
            None,
            data["roles"],
            data.get("password")
        )


class CertificateUsers(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, user_output_schema)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/creator

           Get a certificate's creator

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/creator HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "active": false,
                  "email": "user1@example.com",
                  "username": "user1",
                  "profileImage": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return certificate_service.get(certificate_id).user


class RoleUsers(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, users_output_schema)
    def get(self, role_id):
        """
        .. http:get:: /roles/1/users

           Get all users associated with a role

           **Example request**:

           .. sourcecode:: http

              GET /roles/1/users HTTP/1.1
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
                      "active": True,
                      "email": "user2@example.com",
                      "username": "user2",
                      "profileImage": null
                    },
                    {
                      "id": 1,
                      "active": False,
                      "email": "user1@example.com",
                      "username": "user1",
                      "profileImage": null
                    }
                  ]
                "total": 2
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return role_service.get(role_id).users


class Me(AuthenticatedResource):
    def __init__(self):
        super().__init__()

    @validate_schema(None, user_output_schema)
    def get(self):
        """
        .. http:get:: /auth/me

           Get the currently authenticated user

           **Example request**:

           .. sourcecode:: http

              GET /auth/me HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "active": false,
                  "email": "user1@example.com",
                  "username": "user1",
                  "profileImage": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return g.current_user


api.add_resource(Me, "/auth/me", endpoint="me")
api.add_resource(UsersList, "/users", endpoint="users")
api.add_resource(Users, "/users/<int:user_id>", endpoint="user")
api.add_resource(
    CertificateUsers,
    "/certificates/<int:certificate_id>/creator",
    endpoint="certificateCreator",
)
api.add_resource(RoleUsers, "/roles/<int:role_id>/users", endpoint="roleUsers")
