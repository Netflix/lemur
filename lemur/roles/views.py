"""
.. module: lemur.roles.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import Blueprint
from flask import make_response, jsonify, abort, g
from flask.ext.restful import reqparse, fields, Api

from lemur.roles import service
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import ViewRoleCredentialsPermission, admin_permission
from lemur.common.utils import marshal_items, paginated_parser


mod = Blueprint('roles', __name__)
api = Api(mod)


FIELDS = {
    'name': fields.String,
    'description': fields.String,
    'id': fields.Integer,
}


class RolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(RolesList, self).__init__()

    @marshal_items(FIELDS)
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        parser.add_argument('owner', type=str, location='args')
        parser.add_argument('id', type=str, location='args')

        args = parser.parse_args()
        return service.render(args)

    @admin_permission.require(http_exception=403)
    @marshal_items(FIELDS)
    def post(self):
        """
        .. http:post:: /roles

           Creates a new role

           **Example request**:

           .. sourcecode:: http

              POST /roles HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                 "name": "role3",
                 "description": "this is role3",
                 "username": null,
                 "password": null,
                 "users": []
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
        self.reqparse.add_argument('name', type=str, location='json', required=True)
        self.reqparse.add_argument('description', type=str, location='json')
        self.reqparse.add_argument('username', type=str, location='json')
        self.reqparse.add_argument('password', type=str, location='json')
        self.reqparse.add_argument('users', type=list, location='json')

        args = self.reqparse.parse_args()
        return service.create(args['name'], args.get('password'), args.get('description'), args.get('username'),
                              args.get('users'))


class RoleViewCredentials(AuthenticatedResource):
    def __init__(self):
        super(RoleViewCredentials, self).__init__()

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
                  "username: "ausername",
                  "password": "apassword"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        permission = ViewRoleCredentialsPermission(role_id)
        if permission.can():
            role = service.get(role_id)
            response = make_response(jsonify(username=role.username, password=role.password), 200)
            response.headers['cache-control'] = 'private, max-age=0, no-cache, no-store'
            response.headers['pragma'] = 'no-cache'
            return response
        abort(403)


class Roles(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Roles, self).__init__()

    @marshal_items(FIELDS)
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
        if not g.current_user.is_admin:
            user_role_ids = set([r.id for r in g.current_user.roles])
            if role_id not in user_role_ids:
                return dict(message="You are not allowed to view a role which you are not a member of"), 400

        return service.get(role_id)

    @marshal_items(FIELDS)
    def put(self, role_id):
        """
        .. http:put:: /roles/1

           Update a role

           **Example request**:

           .. sourcecode:: http

              PUT /roles/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

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
        permission = ViewRoleCredentialsPermission(role_id)
        if permission.can():
            self.reqparse.add_argument('name', type=str, location='json', required=True)
            self.reqparse.add_argument('description', type=str, location='json')
            self.reqparse.add_argument('users', type=list, location='json')
            args = self.reqparse.parse_args()
            return service.update(role_id, args['name'], args.get('description'), args.get('users'))
        abort(403)

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
        return {'message': 'ok'}


class UserRolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(UserRolesList, self).__init__()

    @marshal_items(FIELDS)
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['user_id'] = user_id
        return service.render(args)


class AuthorityRolesList(AuthenticatedResource):
    """ Defines the 'roles' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AuthorityRolesList, self).__init__()

    @marshal_items(FIELDS)
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
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair. format is k=v;
           :query limit: limit number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args['authority_id'] = authority_id
        return service.render(args)


api.add_resource(RolesList, '/roles', endpoint='roles')
api.add_resource(Roles, '/roles/<int:role_id>', endpoint='role')
api.add_resource(RoleViewCredentials, '/roles/<int:role_id>/credentials', endpoint='roleCredentials`')
api.add_resource(AuthorityRolesList, '/authorities/<int:authority_id>/roles', endpoint='authorityRoles')
api.add_resource(UserRolesList, '/users/<int:user_id>/roles', endpoint='userRoles')
