"""
.. module: lemur.pending_certificates.views
    :platform: Unix
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""
from flask import Blueprint, g
from flask_restful import Api, reqparse

from lemur.auth.service import AuthenticatedResource
from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.pending_certificates import service
from lemur.pending_certificates.schemas import pending_certificate_output_schema

mod = Blueprint('pending_certificates', __name__)
api = Api(mod)


class PendingCertificatesList(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(PendingCertificatesList, self).__init__()

    @validate_schema(None, pending_certificate_output_schema)
    def get(self):
        """
        .. http:get:: /pending_certificates

           List of certificates

           **Example request**:

           .. sourcecode:: http

              GET /pending_certificates HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "status": null,
                "cn": "*.test.example.net",
                "chain": "",
                "authority": {
                    "active": true,
                    "owner": "secure@example.com",
                    "id": 1,
                    "description": "verisign test authority",
                    "name": "verisign"
                },
                "owner": "joe@example.com",
                "serial": "82311058732025924142789179368889309156",
                "id": 2288,
                "issuer": "SymantecCorporation",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "description": null,
                "deleted": null,
                "notifications": [{
                    "id": 1
                }],
                "signingAlgorithm": "sha256",
                "user": {
                    "username": "jane",
                    "active": true,
                    "email": "jane@example.com",
                    "id": 2
                },
                "active": true,
                "domains": [{
                    "sensitive": false,
                    "id": 1090,
                    "name": "*.test.example.net"
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "replaces": [],
                "replaced": [],
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        parser = paginated_parser.copy()
        parser.add_argument('timeRange', type=int, dest='time_range', location='args')
        parser.add_argument('owner', type=bool, location='args')
        parser.add_argument('id', type=str, location='args')
        parser.add_argument('active', type=bool, location='args')
        parser.add_argument('destinationId', type=int, dest="destination_id", location='args')
        parser.add_argument('creator', type=str, location='args')
        parser.add_argument('show', type=str, location='args')
        args = parser.parse_args()
        args['user'] = g.user
        return service.render(args)


class PendingCertificates(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(PendingCertificates, self).__init__()

    @validate_schema(None, pending_certificate_output_schema)
    def get(self, pending_certificate_id):
        """
        .. http:get:: /pending_certificates/1

           One certificate

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "status": null,
                "cn": "*.test.example.net",
                "chain": "",
                "authority": {
                    "active": true,
                    "owner": "secure@example.com",
                    "id": 1,
                    "description": "verisign test authority",
                    "name": "verisign"
                },
                "owner": "joe@example.com",
                "serial": "82311058732025924142789179368889309156",
                "id": 1,
                "issuer": "SymantecCorporation",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "description": null,
                "deleted": null,
                "notifications": [{
                    "id": 1
                }],
                "signingAlgorithm": "sha256",
                "user": {
                    "username": "jane",
                    "active": true,
                    "email": "jane@example.com",
                    "id": 2
                },
                "active": true,
                "domains": [{
                    "sensitive": false,
                    "id": 1090,
                    "name": "*.test.example.net"
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "replaces": [],
                "replaced": [],
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        return service.get(pending_certificate_id)


api.add_resource(PendingCertificatesList, '/pending_certificates', endpoint='pending_certificates')
api.add_resource(PendingCertificates, '/pending_certificates/<int:pending_certificate_id>', endpoint='pending_certificate')
