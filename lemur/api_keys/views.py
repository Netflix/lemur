"""
.. module: lemur.api_keys.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Eric Coan <kungfury@instructure.com>

"""
from datetime import datetime

from flask import Blueprint, g
from flask_restful import reqparse, Api

from lemur.api_keys import service
from lemur.auth.service import AuthenticatedResource, create_token
from lemur.auth.permissions import ApiKeyCreatorPermission

from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.api_keys.schemas import (
    api_key_input_schema,
    api_key_revoke_schema,
    api_key_output_schema,
    api_keys_output_schema,
    api_key_described_output_schema,
    user_api_key_input_schema,
)

mod = Blueprint("api_keys", __name__)
api = Api(mod)


class ApiKeyList(AuthenticatedResource):
    """ Defines the 'api_keys' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, api_keys_output_schema)
    def get(self):
        """
        .. http:get:: /keys

           The current list of api keys, that you can see.

           **Example request**:

           .. sourcecode:: http

              GET /keys HTTP/1.1
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
                      "name": "custom name",
                      "user_id": 1,
                      "ttl": -1,
                      "issued_at": 12,
                      "revoked": false
                    }
                ],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query count: count number. default is 10
           :query user_id: a user to filter by.
           :query id: an access key to filter by.
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args["has_permission"] = ApiKeyCreatorPermission().can()
        args["requesting_user_id"] = g.current_user.id
        return service.render(args)

    @validate_schema(api_key_input_schema, api_key_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /keys

           Creates an API Key.

           **Example request**:

           .. sourcecode:: http

              POST /keys HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "name": "my custom name",
                "user_id": 1,
                "ttl": -1
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {

                "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if not ApiKeyCreatorPermission().can():
            if data["user"]["id"] != g.current_user.id:
                return (
                    dict(
                        message="You are not authorized to create tokens for: {}".format(
                            data["user"]["username"]
                        )
                    ),
                    403,
                )

        access_token = service.create(
            name=data["name"],
            user_id=data["user"]["id"],
            ttl=data["ttl"],
            revoked=False,
            issued_at=int(datetime.utcnow().timestamp()),
        )
        return dict(
            jwt=create_token(access_token.user_id, access_token.id, access_token.ttl)
        )


class ApiKeyUserList(AuthenticatedResource):
    """ Defines the 'keys' endpoint on the 'users' endpoint. """

    def __init__(self):
        super().__init__()

    @validate_schema(None, api_keys_output_schema)
    def get(self, user_id):
        """
        .. http:get:: /users/:user_id/keys

           The current list of api keys for a user, that you can see.

           **Example request**:

           .. sourcecode:: http

              GET /users/1/keys HTTP/1.1
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
                      "name": "custom name",
                      "user_id": 1,
                      "ttl": -1,
                      "issued_at": 12,
                      "revoked": false
                    }
                ],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query count: count number. default is 10
           :query id: an access key to filter by.
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args["has_permission"] = ApiKeyCreatorPermission().can()
        args["requesting_user_id"] = g.current_user.id
        args["user_id"] = user_id
        return service.render(args)

    @validate_schema(user_api_key_input_schema, api_key_output_schema)
    def post(self, user_id, data=None):
        """
        .. http:post:: /users/:user_id/keys

           Creates an API Key for a user.

           **Example request**:

           .. sourcecode:: http

              POST /users/1/keys HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "name": "my custom name"
                "ttl": -1
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {

                "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if not ApiKeyCreatorPermission().can():
            if user_id != g.current_user.id:
                return (
                    dict(
                        message="You are not authorized to create tokens for: {}".format(
                            user_id
                        )
                    ),
                    403,
                )

        access_token = service.create(
            name=data["name"],
            user_id=user_id,
            ttl=data["ttl"],
            revoked=False,
            issued_at=int(datetime.utcnow().timestamp()),
        )
        return dict(
            jwt=create_token(access_token.user_id, access_token.id, access_token.ttl)
        )


class ApiKeys(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, api_key_output_schema)
    def get(self, aid):
        """
        .. http:get:: /keys/1

           Fetch one api key

           **Example request**:

           .. sourcecode:: http

              GET /keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        access_key = service.get(aid)

        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to view this token!"), 403

        return dict(jwt=create_token(access_key.user_id, access_key.id, access_key.ttl))

    @validate_schema(api_key_revoke_schema, api_key_output_schema)
    def put(self, aid, data=None):
        """
        .. http:put:: /keys/1

           update one api key

           **Example request**:

           .. sourcecode:: http

              PUT /keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                  "name": "new_name",
                  "revoked": false,
                  "ttl": -1
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        access_key = service.get(aid)
        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to update this token!"), 403

        service.update(
            access_key, name=data["name"], revoked=data["revoked"], ttl=data["ttl"]
        )
        return dict(jwt=create_token(access_key.user_id, access_key.id, access_key.ttl))

    def delete(self, aid):
        """
        .. http:delete:: /keys/1

           deletes one api key

           **Example request**:

           .. sourcecode:: http

              DELETE /keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "result": true
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        access_key = service.get(aid)
        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to delete this token!"), 403

        service.delete(access_key)
        return {"result": True}


class UserApiKeys(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, api_key_output_schema)
    def get(self, uid, aid):
        """
        .. http:get:: /users/1/keys/1

           Fetch one api key

           **Example request**:

           .. sourcecode:: http

              GET /users/1/api_keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if uid != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to view this token!"), 403

        access_key = service.get(aid)

        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != uid:
            return dict(message="You are not authorized to view this token!"), 403

        return dict(jwt=create_token(access_key.user_id, access_key.id, access_key.ttl))

    @validate_schema(api_key_revoke_schema, api_key_output_schema)
    def put(self, uid, aid, data=None):
        """
        .. http:put:: /users/1/keys/1

           update one api key

           **Example request**:

           .. sourcecode:: http

              PUT /users/1/keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                  "name": "new_name",
                  "revoked": false,
                  "ttl": -1
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "jwt": ""
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if uid != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to view this token!"), 403

        access_key = service.get(aid)
        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != uid:
            return dict(message="You are not authorized to update this token!"), 403

        service.update(
            access_key, name=data["name"], revoked=data["revoked"], ttl=data["ttl"]
        )
        return dict(jwt=create_token(access_key.user_id, access_key.id, access_key.ttl))

    def delete(self, uid, aid):
        """
        .. http:delete:: /users/1/keys/1

           deletes one api key

           **Example request**:

           .. sourcecode:: http

              DELETE /users/1/keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "result": true
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        if uid != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to view this token!"), 403

        access_key = service.get(aid)
        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != uid:
            return dict(message="You are not authorized to delete this token!"), 403

        service.delete(access_key)
        return {"result": True}


class ApiKeysDescribed(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, api_key_described_output_schema)
    def get(self, aid):
        """
        .. http:get:: /keys/1/described

           Fetch one api key

           **Example request**:

           .. sourcecode:: http

              GET /keys/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "id": 2,
                  "name": "hoi",
                  "user_id": 2,
                  "ttl": -1,
                  "issued_at": 1222222,
                  "revoked": false
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        access_key = service.get(aid)
        if access_key is None:
            return dict(message="This token does not exist!"), 404

        if access_key.user_id != g.current_user.id:
            if not ApiKeyCreatorPermission().can():
                return dict(message="You are not authorized to view this token!"), 403

        return access_key


api.add_resource(ApiKeyList, "/keys", endpoint="api_keys")
api.add_resource(ApiKeys, "/keys/<int:aid>", endpoint="api_key")
api.add_resource(
    ApiKeysDescribed, "/keys/<int:aid>/described", endpoint="api_key_described"
)
api.add_resource(ApiKeyUserList, "/users/<int:user_id>/keys", endpoint="user_api_keys")
api.add_resource(
    UserApiKeys, "/users/<int:uid>/keys/<int:aid>", endpoint="user_api_key"
)
