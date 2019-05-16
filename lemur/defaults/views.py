"""
.. module: lemur.defaults.views
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask import current_app, Blueprint
from flask_restful import Api

from lemur.common.schema import validate_schema
from lemur.authorities.service import get_by_name
from lemur.auth.service import AuthenticatedResource

from lemur.defaults.schemas import default_output_schema


mod = Blueprint("default", __name__)
api = Api(mod)


class LemurDefaults(AuthenticatedResource):
    """ Defines the 'defaults' endpoint """

    def __init__(self):
        super(LemurDefaults)

    @validate_schema(None, default_output_schema)
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
                 "organizationalUnit": "Operations",
                 "dnsProviders": [{"name": "test", ...}, {...}],
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """

        default_authority = get_by_name(
            current_app.config.get("LEMUR_DEFAULT_AUTHORITY")
        )

        return dict(
            country=current_app.config.get("LEMUR_DEFAULT_COUNTRY"),
            state=current_app.config.get("LEMUR_DEFAULT_STATE"),
            location=current_app.config.get("LEMUR_DEFAULT_LOCATION"),
            organization=current_app.config.get("LEMUR_DEFAULT_ORGANIZATION"),
            organizational_unit=current_app.config.get(
                "LEMUR_DEFAULT_ORGANIZATIONAL_UNIT"
            ),
            issuer_plugin=current_app.config.get("LEMUR_DEFAULT_ISSUER_PLUGIN"),
            authority=default_authority,
        )


api.add_resource(LemurDefaults, "/defaults", endpoint="default")
