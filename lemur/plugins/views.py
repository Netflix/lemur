"""
.. module: lemur.plugins.views
    :platform: Unix
    :synopsis: This module contains all of the accounts view code.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from flask.ext.restful import Api, reqparse, fields
from lemur.auth.service import AuthenticatedResource

from lemur.common.utils import marshal_items

from lemur.plugins.base import plugins

mod = Blueprint('plugins', __name__)
api = Api(mod)


FIELDS = {
    'title': fields.String,
    'pluginOptions': fields.Raw(attribute='options'),
    'description': fields.String,
    'version': fields.String,
    'author': fields.String,
    'authorUrl': fields.String,
    'type': fields.String,
    'slug': fields.String,
}


class PluginsList(AuthenticatedResource):
    """ Defines the 'plugins' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(PluginsList, self).__init__()

    @marshal_items(FIELDS)
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
                      "comments": "this is a thing"
                    },
                    {
                      "id": 1,
                      "accountNumber": 11111111111,
                      "label": "account1",
                      "comments": "this is a thing"
                    },
                  ]
                "total": 2
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return plugins.all()


class PluginsTypeList(AuthenticatedResource):
    """ Defines the 'plugins' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(PluginsTypeList, self).__init__()

    @marshal_items(FIELDS)
    def get(self, plugin_type):
        """
        .. http:get:: /plugins/issuer

           The current plugin list

           **Example request**:

           .. sourcecode:: http

              GET /plugins/issuer HTTP/1.1
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
                      "comments": "this is a thing"
                    },
                    {
                      "id": 1,
                      "accountNumber": 11111111111,
                      "label": "account1",
                      "comments": "this is a thing"
                    },
                  ]
                "total": 2
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
        """
        return list(plugins.all(plugin_type=plugin_type))

api.add_resource(PluginsList, '/plugins', endpoint='plugins')
api.add_resource(PluginsTypeList, '/plugins/<plugin_type>', endpoint='pluginType')

