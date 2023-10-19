"""
.. module: lemur.plugins.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask_restful import Api, reqparse
from lemur.auth.service import AuthenticatedResource


from lemur.schemas import plugins_output_schema, plugin_output_schema
from lemur.common.schema import validate_schema
from lemur.plugins.base import plugins

mod = Blueprint("plugins", __name__)
api = Api(mod)


class PluginsList(AuthenticatedResource):
    """ Defines the 'plugins' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, plugins_output_schema)
    def get(self):
        """
        .. http:get:: /plugins

           The current plugin list

           **Example request**:

           .. sourcecode:: http

              GET /plugins HTTP/1.1
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
                      "description": "this is a thing"
                    },
                    {
                      "id": 1,
                      "accountNumber": 11111111111,
                      "label": "account1",
                      "description": "this is a thing"
                    },
                  ]
                "total": 2
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        self.reqparse.add_argument("type", type=str, location="args")
        args = self.reqparse.parse_args()

        if args["type"]:
            return list(plugins.all(plugin_type=args["type"]))

        return list(plugins.all())


class Plugins(AuthenticatedResource):
    """ Defines the 'plugins' endpoint """

    def __init__(self):
        super().__init__()

    @validate_schema(None, plugin_output_schema)
    def get(self, name):
        """
        .. http:get:: /plugins/<name>

           The current plugin list

           **Example request**:

           .. sourcecode:: http

              GET /plugins HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                  "accountNumber": 222222222,
                  "label": "account2",
                  "description": "this is a thing"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return plugins.get(name)


api.add_resource(PluginsList, "/plugins", endpoint="plugins")
api.add_resource(Plugins, "/plugins/<name>", endpoint="pluginName")
