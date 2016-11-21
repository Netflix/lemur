"""
.. module: lemur.status.views
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask import current_app, Blueprint
from flask.ext.restful import Api

from lemur.auth.service import AuthenticatedResource


mod = Blueprint('default', __name__)
api = Api(mod)


class LemurDefaults(AuthenticatedResource):
    """ Defines the 'defaults' endpoint """
    def __init__(self):
        super(LemurDefaults)

    def get(self):
        """
        .. http:get:: /defaults

            Returns defaults needed to generate CSRs

           **Example request**:

           .. sourcecode:: http

              GET /defaults HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "country": "US",
                 "state": "CA",
                 "location": "Los Gatos",
                 "organization": "Netflix",
                 "organizationalUnit": "Operations"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return dict(
            country=current_app.config.get('LEMUR_DEFAULT_COUNTRY'),
            state=current_app.config.get('LEMUR_DEFAULT_STATE'),
            location=current_app.config.get('LEMUR_DEFAULT_LOCATION'),
            organization=current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'),
            organizationalUnit=current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'),
            issuerPlugin=current_app.config.get('LEMUR_DEFAULT_ISSUER_PLUGIN')
        )


api.add_resource(LemurDefaults, '/defaults', endpoint='default')
