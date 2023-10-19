"""
.. module: lemur.roles.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint, g
from flask import make_response, jsonify
from flask_restful import reqparse, Api

from lemur.roles import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import RoleMemberPermission, admin_permission
from lemur.common.utils import paginated_parser
from lemur.logs import service as log_service

from lemur.common.schema import validate_schema
from lemur.roles.schemas import (
    role_input_schema,
    role_output_schema,
    roles_output_schema,
)


mod = Blueprint("roles", __name__)
api = Api(mod)


class RolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, roles_output_schema)
    def get(self):
        """
        .. http:get:: /roles

           The current role list

           **Example request**:

           .. sourcecode:: http

              GET /roles HTTP/1.1
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
                      "name": "role1",
                      "description": "this is role1"
                    },
                    {
                      "id": 2,
                      "name": "role2",
                      "description": "this is role2"
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
        parser.add_argument("owner", type=str, location="args")
        parser.add_argument("id", type=str, location="args")

        args = parser.parse_args()
        args["user"] = g.current_user
        return service.render(args)

    @validate_schema(role_input_schema, role_output_schema)
    @admin_permission.require(http_exception=403)
    def post(self, data=None):
        """
        .. http:post:: /roles

           Creates a new role

           **Example request**:

           .. sourcecode:: http

              POST /roles HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "name": "role3",
                 "description": "this is role3",
                 "username": null,
                 "password": null,
                 "users": [
                    {"id": 1}
                 ]
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 3,
                  "description": "this is role3",
                  "name": "role3"
              }

           :arg name: name for new role
           :arg description: description for new role
           :arg password: password for new role
           :arg username: username for new role
           :arg users: list, of users to associate with role
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.create(
            data["name"],
            data.get("password"),
            data.get("description"),
            data.get("username"),
            data.get("users"),
        )


class RoleViewCredentials(AuthenticatedResource):
    def __init__(self):
        super().__init__()

    def get(self, role_id):
        """
        .. http:get:: /roles/1/credentials

           View a roles credentials

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
                  "username": "ausername",
                  "password": "apassword"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        permission = RoleMemberPermission(role_id)
        if permission.can():
            role = service.get(role_id)
            response = make_response(
                jsonify(username=role.username, password=role.password), 200
            )
            response.headers["cache-control"] = "private, max-age=0, no-cache, no-store"
            response.headers["pragma"] = "no-cache"

            log_service.audit_log("view_role_credentials", role.name, "View role username and password")

            return response
        return (
            dict(
                message="You are not authorized to view the credentials for this role."
            ),
            403,
        )


class Roles(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, role_output_schema)
    def get(self, role_id):
        """
        .. http:get:: /roles/1

           Get a particular role

           **Example request**:

           .. sourcecode:: http

              GET /roles/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 1,
                  "name": "role1",
                  "description": "this is role1"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        # we want to make sure that we cannot view roles that we are not members of
        permission = RoleMemberPermission(role_id)
        if permission.can():
            return service.get(role_id)

        return (
            dict(
                message="You are not allowed to view a role which you are not a member of."
            ),
            403,
        )

    @validate_schema(role_input_schema, role_output_schema)
    def put(self, role_id, data=None):
        """
        .. http:put:: /roles/1

           Update a role

           **Example request**:

           .. sourcecode:: http

              PUT /roles/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "name": "role1",
                 "description": "This is a new description"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "id": 1,
                 "name": "role1",
                 "description": "this is a new description"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        permission = RoleMemberPermission(role_id)
        if permission.can():
            return service.update(
                role_id, data["name"], data.get("description"), data.get("users")
            )
        return dict(message="You are not authorized to modify this role."), 403

    @admin_permission.require(http_exception=403)
    def delete(self, role_id):
        """
        .. http:delete:: /roles/1

           Delete a role

           **Example request**:

           .. sourcecode:: http

              DELETE /roles/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "message": "ok"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        service.delete(role_id)
        return {"message": "ok"}


class UserRolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, roles_output_schema)
    def get(self, user_id):
        """
        .. http:get:: /users/1/roles

           List of roles for a given user

           **Example request**:

           .. sourcecode:: http

              GET /users/1/roles HTTP/1.1
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
                      "name": "role1",
                      "description": "this is role1"
                    },
                    {
                      "id": 2,
                      "name": "role2",
                      "description": "this is role2"
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
        args = parser.parse_args()
        args["user_id"] = user_id
        return service.render(args)


class AuthorityRolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, roles_output_schema)
    def get(self, authority_id):
        """
        .. http:get:: /authorities/1/roles

           List of roles for a given authority

           **Example request**:

           .. sourcecode:: http

              GET /authorities/1/roles HTTP/1.1
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
                      "name": "role1",
                      "description": "this is role1"
                    },
                    {
                      "id": 2,
                      "name": "role2",
                      "description": "this is role2"
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
        args = parser.parse_args()
        args["authority_id"] = authority_id
        return service.render(args)


api.add_resource(RolesList, "/roles", endpoint="roles")
api.add_resource(Roles, "/roles/<int:role_id>", endpoint="role")
api.add_resource(
    RoleViewCredentials, "/roles/<int:role_id>/credentials", endpoint="roleCredentials`"
)
api.add_resource(
    AuthorityRolesList,
    "/authorities/<int:authority_id>/roles",
    endpoint="authorityRoles",
)
api.add_resource(UserRolesList, "/users/<int:user_id>/roles", endpoint="userRoles")
