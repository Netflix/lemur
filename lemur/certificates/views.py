"""
.. module: lemur.certificates.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import base64

from flask import Blueprint, make_response, jsonify, g, current_app
from flask_restful import reqparse, Api, inputs

from lemur.certificates.service import validate_no_duplicate_destinations
from lemur.common import validators
from lemur.plugins.bases.authorization import UnauthorizedError
from sentry_sdk import capture_exception

from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import AuthorityPermission, CertificatePermission, StrictRolePermission

from lemur.certificates import service
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import (
    certificate_input_schema,
    certificate_output_schema,
    certificate_upload_input_schema,
    certificates_output_schema,
    certificate_export_input_schema,
    certificate_edit_input_schema,
    certificates_list_output_schema_factory,
    certificate_revoke_schema,
)

from lemur.roles import service as role_service
from lemur.logs import service as log_service


mod = Blueprint("certificates", __name__)
api = Api(mod)


class CertificatesListValid(AuthenticatedResource):
    """ Defines the 'certificates/valid' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificates_output_schema)
    def get(self):
        """
        .. http:get:: /certificates/valid/<query>

           The current list of not-expired certificates for a given common name, and owner. The API offers
           optional pagination. One can send page number(>=1) and desired count per page. The returned data
           contains total number of certificates which can help in determining the last page. Pagination
           will not be offered if page or count info is not sent or if it is zero.

           **Example request**:

           .. sourcecode:: http

              GET /certificates/valid?filter=cn;*.test.example.net&owner=joe@example.com&page=1&count=20 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response (with single cert to be concise)**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "status": null,
                    "cn": "*.test.example.net",
                    "chain": "",
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----"
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
                    "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                    "notBefore": "2016-06-03T00:00:00+00:00",
                    "notAfter": "2018-01-12T23:59:59+00:00",
                    "destinations": [],
                    "bits": 2048,
                    "body": "-----BEGIN CERTIFICATE-----...",
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
                    "replaces": [],
                    "replaced": [],
                    "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                    "roles": [{
                        "id": 464,
                        "description": "This is a google group based role created by Lemur",
                        "name": "joe@example.com"
                    }],
                    "san": null
                }],
                "total": 1
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        # using non-paginated parser to ensure backward compatibility
        self.reqparse.add_argument("filter", type=str, location="args")
        self.reqparse.add_argument("owner", type=str, location="args")
        self.reqparse.add_argument("san", type=str, location="args")
        self.reqparse.add_argument("count", type=int, location="args")
        self.reqparse.add_argument("page", type=int, location="args")

        args = self.reqparse.parse_args()
        args["user"] = g.user
        common_name = args.pop("filter").split(";")[1]
        return service.query_common_name(common_name, args)


class CertificatesNameQuery(AuthenticatedResource):
    """ Defines the 'certificates/name' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificates_output_schema)
    def get(self, certificate_name):
        """
        .. http:get:: /certificates/name/<query>

           The current list of certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates/name/WILDCARD.test.example.net-SymantecCorporation-20160603-20180112 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "status": null,
                    "cn": "*.test.example.net",
                    "chain": "",
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----"
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
                    "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                    "notBefore": "2016-06-03T00:00:00+00:00",
                    "notAfter": "2018-01-12T23:59:59+00:00",
                    "destinations": [],
                    "bits": 2048,
                    "body": "-----BEGIN CERTIFICATE-----...",
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
                    "replaces": [],
                    "replaced": [],
                    "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                    "roles": [{
                        "id": 464,
                        "description": "This is a google group based role created by Lemur",
                        "name": "joe@example.com"
                    }],
                    "san": null
                }],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int. default is 1
           :query filter: key value pair format is k;v
           :query count: count number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        parser = paginated_parser.copy()
        parser.add_argument("timeRange", type=int, dest="time_range", location="args")
        parser.add_argument("owner", type=inputs.boolean, location="args")
        parser.add_argument("id", type=str, location="args")
        parser.add_argument("active", type=inputs.boolean, location="args")
        parser.add_argument(
            "destinationId", type=int, dest="destination_id", location="args"
        )
        parser.add_argument("creator", type=str, location="args")
        parser.add_argument("show", type=str, location="args")

        args = parser.parse_args()
        args["user"] = g.user
        return service.query_name(certificate_name, args)


class CertificatesList(AuthenticatedResource):
    """ Defines the 'certificates' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificates_list_output_schema_factory)
    def get(self):
        """
        .. http:get:: /certificates

            The current list of certificates. This API supports additional params like

            Pagination, sorting:
                /certificates?count=10&page=1&short=true&sortBy=id&sortDir=desc
            Filters, mentioned as url param filter=field;value
                /certificates?filter=cn;lemur.test.com
                /certificates?filter=notify;true
                /certificates?filter=rotation;true
                /certificates?filter=name;lemur.test.cert
                /certificates?filter=issuer;Digicert
            Request expired certs
                /certificates?showExpired=1
            Search by Serial Number
                Decimal:
                /certificates?serial=218243997808053074560741989466015229225
                Hex:
                /certificates?serial=0xA43043DAB7F6F8AE115E94854EEB6529
                /certificates?serial=a4:30:43:da:b7:f6:f8:ae:11:5e:94:85:4e:eb:65:29


           **Example request**:

           .. sourcecode:: http

              GET /certificates?serial=82311058732025924142789179368889309156 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "status": null,
                    "cn": "*.test.example.net",
                    "chain": "",
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----"
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
                    "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                    "notBefore": "2016-06-03T00:00:00+00:00",
                    "notAfter": "2018-01-12T23:59:59+00:00",
                    "destinations": [],
                    "bits": 2048,
                    "body": "-----BEGIN CERTIFICATE-----...",
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
                    "replaces": [],
                    "replaced": [],
                    "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                    "roles": [{
                        "id": 464,
                        "description": "This is a google group based role created by Lemur",
                        "name": "joe@example.com"
                    }],
                    "san": null
                }],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int. default is 1
           :query filter: key value pair format is k;v
           :query count: count number. default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        parser = paginated_parser.copy()
        parser.add_argument("timeRange", type=int, dest="time_range", location="args")
        parser.add_argument("owner", type=inputs.boolean, location="args")
        parser.add_argument("id", type=str, location="args")
        parser.add_argument("active", type=inputs.boolean, location="args")
        parser.add_argument("rotation", type=inputs.boolean, location="args")
        parser.add_argument(
            "destinationId", type=int, dest="destination_id", location="args"
        )
        parser.add_argument("creator", type=str, location="args")
        parser.add_argument("show", type=str, location="args")
        parser.add_argument("showExpired", type=int, location="args")
        parser.add_argument("serial", type=str, location="args")

        args = parser.parse_args()
        args["user"] = g.user
        return service.render(args)

    @validate_schema(certificate_input_schema, certificate_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /certificates

           Creates a new certificate

           **Example request**:

           .. sourcecode:: http

              POST /certificates HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                  "owner": "secure@example.net",
                  "commonName": "test.example.net",
                  "country": "US",
                  "extensions": {
                    "subAltNames": {
                      "names": [
                        {
                          "nameType": "DNSName",
                          "value": "*.test.example.net"
                        },
                        {
                          "nameType": "DNSName",
                          "value": "www.test.example.net"
                        }
                      ]
                    }
                  },
                  "replacements": [{
                    "id": 1
                  }],
                  "notify": true,
                  "validityEnd": "2026-01-01T08:00:00.000Z",
                  "authority": {
                    "name": "verisign"
                  },
                  "organization": "Netflix, Inc.",
                  "location": "Los Gatos",
                  "state": "California",
                  "validityStart": "2016-11-11T04:19:48.000Z",
                  "organizationalUnit": "Operations"
              }


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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
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
                "replaces": [{
                    "id": 1
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
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
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to create a new certificate."), 403

        if not validators.is_valid_owner(data["owner"]):
            return dict(message=f"Invalid owner: check if {data['owner']} is a valid group email. Individuals cannot be certificate owners."), 412

        role = role_service.get_by_name(data["authority"].owner)

        # all the authority role members should be allowed
        roles = [x.name for x in data["authority"].roles]

        # allow "owner" roles by team DL
        roles.append(role)
        authority_permission = AuthorityPermission(data["authority"].id, roles)

        if not authority_permission.can():
            return dict(message=f"You are not authorized to use the authority: {data['authority'].name}"), 403

        data["creator"] = g.user
        # allowed_issuance_for_domain throws UnauthorizedError if caller is not authorized
        try:
            # unless admin or global_cert_issuer, perform fine grained authorization
            if not g.user.is_admin_or_global_cert_issuer and not data["authority"].is_private_authority:
                service.allowed_issuance_for_domain(data["common_name"], data["extensions"])
        except UnauthorizedError as e:
            return dict(message=str(e)), 403
        else:
            cert = service.create(**data)
            if isinstance(cert, Certificate):
                # only log if created, not pending
                log_service.create(g.user, "create_cert", certificate=cert)
            return cert


class CertificatesUpload(AuthenticatedResource):
    """ Defines the 'certificates' upload endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(certificate_upload_input_schema, certificate_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /certificates/upload

           Upload a certificate

           **Example request**:

           .. sourcecode:: http

              POST /certificates/upload HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "owner": "joe@example.com",
                 "body": "-----BEGIN CERTIFICATE-----...",
                 "chain": "-----BEGIN CERTIFICATE-----...",
                 "privateKey": "-----BEGIN RSA PRIVATE KEY-----..."
                 "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
                 "destinations": [],
                 "notifications": [],
                 "replacements": [],
                 "roles": [],
                 "notify": true,
                 "name": "cert1"
              }

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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
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
                "replaces": [],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 403: unauthenticated
           :statuscode 200: no error

        """
        if not StrictRolePermission().can():
            return dict(message="You are not authorized to upload a certificate."), 403

        data["creator"] = g.user
        if data.get("destinations"):
            if data.get("private_key"):
                return service.upload(**data)
            else:
                raise Exception(
                    "Private key must be provided in order to upload certificate to AWS"
                )
        return service.upload(**data)


class CertificatesStats(AuthenticatedResource):
    """ Defines the 'certificates' stats endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def get(self):
        self.reqparse.add_argument("metric", type=str, location="args")
        self.reqparse.add_argument("range", default=32, type=int, location="args")
        self.reqparse.add_argument(
            "destinationId", dest="destination_id", location="args"
        )
        self.reqparse.add_argument("active", type=str, default="true", location="args")

        args = self.reqparse.parse_args()

        try:
            items = service.stats(**args)
        except Exception as e:
            capture_exception()
            return dict(message=f"Failed to retrieve stats: {str(e)}"), 400

        return dict(items=items, total=len(items))


class CertificatePrivateKey(AuthenticatedResource):
    def __init__(self):
        super().__init__()

    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/key

           Retrieves the private key for a given certificate

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/key HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "key": "-----BEGIN ..."
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        cert = service.get(certificate_id)
        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return dict(message="You are not authorized to view this key"), 403

        log_service.create(g.current_user, "key_view", certificate=cert)
        response = make_response(jsonify(key=cert.private_key), 200)
        response.headers["cache-control"] = "private, max-age=0, no-cache, no-store"
        response.headers["pragma"] = "no-cache"

        log_service.audit_log("export_private_key", cert.name,
                              "Exported Private key for the certificate")
        return response


class Certificates(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificate_output_schema)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1

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
                "csr": "-----BEGIN CERTIFICATE REQUEST-----"
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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
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
        return service.get(certificate_id)

    @validate_schema(certificate_edit_input_schema, certificate_output_schema)
    def put(self, certificate_id, data=None):
        """
        .. http:put:: /certificates/1

           Update a certificate

           **Example request**:

           .. sourcecode:: http

              PUT /certificates/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "owner": "jimbob@example.com",
                 "active": false
                 "notifications": [],
                 "destinations": [],
                 "replacements": []
              }

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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
                "description": null,
                "deleted": null,
                "notifications": [{
                    "id": 1
                }]
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
                "replaces": [],
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to update this certificate"),
                    403,
                )

        try:
            validate_no_duplicate_destinations(data["destinations"])
        except Exception as e:
            return (
                dict(message=str(e)),
                400,
            )

        for destination in data["destinations"]:
            if destination.plugin.requires_key:
                if not cert.private_key:
                    return (
                        dict(
                            message="Unable to add destination: {}. Certificate does not have required private key.".format(
                                destination.label
                            )
                        ),
                        400,
                    )

        # if owner is changed, validate owner and remove all notifications and roles associated with old owner
        if cert.owner != data["owner"]:
            if not validators.is_valid_owner(data["owner"]):
                return dict(message=f"Invalid owner: check if {data['owner']} is a valid group email. Individuals cannot "
                                    f"be authority owners."), 412
            service.cleanup_owner_roles_notification(cert.owner, data)

        error_message = ""
        # if destination is removed, cleanup the certificate from AWS
        for destination in cert.destinations:
            if destination not in data["destinations"]:
                try:
                    service.remove_from_destination(cert, destination)
                except Exception as e:
                    capture_exception()
                    # Add the removed destination back
                    data["destinations"].append(destination)
                    error_message = error_message + f"Failed to remove destination: {destination.label}. {str(e)}. "

        # go ahead with DB update
        cert = service.update(certificate_id, **data)
        log_service.create(g.current_user, "update_cert", certificate=cert)

        if error_message:
            return dict(message=f"Edit Successful except -\n\n {error_message}"), 400
        return cert

    @validate_schema(certificate_edit_input_schema, certificate_output_schema)
    def post(self, certificate_id, data=None):
        """
        .. http:post:: /certificates/1/update/switches

           Update certificate boolean switches for notification or rotation

           **Example request**:

           .. sourcecode:: http

              POST /certificates/1/update/switches HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "notify": false,
                 "rotation": false
              }

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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
                "description": null,
                "deleted": null,
                "notify": false,
                "rotation": false,
                "notifications": [{
                    "id": 1
                }]
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
                "replaces": [],
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to update this certificate"),
                    403,
                )

        cert = service.update_switches(cert, notify_flag=data.get("notify"), rotation_flag=data.get("rotation"))
        log_service.create(g.current_user, "update_cert", certificate=cert)
        return cert

    def delete(self, certificate_id, data=None):
        """
        .. http:delete:: /certificates/1

           Delete a certificate

           **Example request**:

           .. sourcecode:: http

              DELETE /certificates/1 HTTP/1.1
              Host: example.com

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 204 OK

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 204: no error
           :statuscode 403: unauthenticated
           :statuscode 404: certificate not found
           :statuscode 405: certificate deletion is disabled

        """
        if not current_app.config.get("ALLOW_CERT_DELETION", False):
            return dict(message="Certificate deletion is disabled"), 405

        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        if cert.deleted:
            return dict(message="Certificate is already deleted"), 412

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to delete this certificate"),
                    403,
                )

        service.update(certificate_id, deleted=True)
        log_service.create(g.current_user, "delete_cert", certificate=cert)
        return "Certificate deleted", 204


class CertificateUpdateOwner(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(certificate_edit_input_schema, certificate_output_schema)
    def post(self, certificate_id, data=None):
        """
        .. http:post:: /certificates/1/update/owner

           Update certificate owner

           **Example request**:

           .. sourcecode:: http

              POST /certificates/1/update/owner HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "owner": "joan@example.com"
              }

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
                "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                "notBefore": "2016-06-03T00:00:00+00:00",
                "notAfter": "2018-01-12T23:59:59+00:00",
                "destinations": [],
                "bits": 2048,
                "body": "-----BEGIN CERTIFICATE-----...",
                "description": null,
                "deleted": null,
                "notify": false,
                "rotation": false,
                "notifications": [{
                    "id": 1
                }]
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
                "replaces": [],
                "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                "roles": [{
                    "id": 464,
                    "description": "This is a google group based role created by Lemur",
                    "name": "joe@example.com"
                }],
                "rotation": true,
                "rotationPolicy": {"name": "default"},
                "san": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        if not validators.is_valid_owner(data["owner"]):
            return dict(message=f"Invalid owner: check if {data['owner']} is a valid group email. Individuals cannot "
                                f"be authority owners."), 412

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to update this certificate"),
                    403,
                )

        cert = service.update_owner(cert, data)

        log_service.create(g.current_user, "update_cert", certificate=cert)
        return cert


class NotificationCertificatesList(AuthenticatedResource):
    """ Defines the 'certificates' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificates_output_schema)
    def get(self, notification_id):
        """
        .. http:get:: /notifications/1/certificates

           The current list of certificates for a given notification

           **Example request**:

           .. sourcecode:: http

              GET /notifications/1/certificates HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "status": null,
                    "cn": "*.test.example.net",
                    "chain": "",
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----"
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
                    "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                    "notBefore": "2016-06-03T00:00:00+00:00",
                    "notAfter": "2018-01-12T23:59:59+00:00",
                    "destinations": [],
                    "bits": 2048,
                    "body": "-----BEGIN CERTIFICATE-----...",
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
                    "replaces": [],
                    "replaced": [],
                    "rotation": true,
                    "rotationPolicy": {"name": "default"},
                    "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                    "roles": [{
                        "id": 464,
                        "description": "This is a google group based role created by Lemur",
                        "name": "joe@example.com"
                    }],
                    "san": null
                }],
                "total": 1
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
        parser.add_argument("timeRange", type=int, dest="time_range", location="args")
        parser.add_argument("owner", type=inputs.boolean, location="args")
        parser.add_argument("id", type=str, location="args")
        parser.add_argument("active", type=inputs.boolean, location="args")
        parser.add_argument(
            "destinationId", type=int, dest="destination_id", location="args"
        )
        parser.add_argument("creator", type=str, location="args")
        parser.add_argument("show", type=str, location="args")
        parser.add_argument("showExpired", type=int, location="args")

        args = parser.parse_args()
        args["notification_id"] = notification_id
        args["user"] = g.current_user
        return service.render(args)


class CertificatesReplacementsList(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, certificates_output_schema)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/replacements

           One certificate

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/replacements HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "items": [{
                    "status": null,
                    "cn": "*.test.example.net",
                    "chain": "",
                    "csr": "-----BEGIN CERTIFICATE REQUEST-----",
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
                    "dateCreated": "2016-06-03T06:09:42.133769+00:00",
                    "notBefore": "2016-06-03T00:00:00+00:00",
                    "notAfter": "2018-01-12T23:59:59+00:00",
                    "destinations": [],
                    "bits": 2048,
                    "body": "-----BEGIN CERTIFICATE-----...",
                    "description": null,
                    "deleted": null,
                    "notifications": [{
                        "id": 1
                    }]
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
                    "replaces": [],
                    "replaced": [],
                    "rotation": true,
                    "rotationPolicy": {"name": "default"},
                    "name": "WILDCARD.test.example.net-SymantecCorporation-20160603-20180112",
                    "roles": [{
                        "id": 464,
                        "description": "This is a google group based role created by Lemur",
                        "name": "joe@example.com"
                    }],
                    "san": null
                }],
                "total": 1
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        return service.get(certificate_id).replaces


class CertificateExport(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(certificate_export_input_schema, None)
    def post(self, certificate_id, data=None):
        """
        .. http:post:: /certificates/1/export

           Export a certificate

           **Example request**:

           .. sourcecode:: http

              PUT /certificates/1/export HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "export": {
                    "plugin": {
                        "pluginOptions": [{
                            "available": ["Java Key Store (JKS)"],
                            "required": true,
                            "type": "select",
                            "name": "type",
                            "helpMessage": "Choose the format you wish to export",
                            "value": "Java Key Store (JKS)"
                        }, {
                            "required": false,
                            "type": "str",
                            "name": "passphrase",
                            "validation": "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[$@$!%*#?&])[A-Za-z\\d$@$!%*#?&]{8,}$",
                            "helpMessage": "If no passphrase is given one will be generated for you, we highly recommend this. Minimum length is 8."
                        }, {
                            "required": false,
                            "type": "str",
                            "name": "alias",
                            "helpMessage": "Enter the alias you wish to use for the keystore."
                        }],
                        "version": "unknown",
                        "description": "Attempts to generate a JKS keystore or truststore",
                        "title": "Java",
                        "author": "Kevin Glisson",
                        "type": "export",
                        "slug": "java-export"
                    }
                }
              }


           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "data": "base64encodedstring",
                "passphrase": "UAWOHW#&@_%!tnwmxh832025",
                "extension": "jks"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        plugin = data["plugin"]["plugin_object"]

        if plugin.requires_key:
            if not cert.private_key:
                return (
                    dict(
                        message="Unable to export certificate, plugin: {} requires a private key but no key was found.".format(
                            plugin.slug
                        )
                    ),
                    400,
                )

            else:
                # allow creators
                if g.current_user != cert.user:
                    owner_role = role_service.get_by_name(cert.owner)
                    permission = CertificatePermission(
                        owner_role, [x.name for x in cert.roles]
                    )

                    if not permission.can():
                        return (
                            dict(
                                message="You are not authorized to export this certificate."
                            ),
                            403,
                        )

        options = data["plugin"]["plugin_options"]

        log_service.create(g.current_user, "key_view", certificate=cert)
        extension, passphrase, data = plugin.export(
            cert.body, cert.chain, cert.private_key, options
        )

        # Clear memory for last passphrase if it's in plugin.options
        for option in plugin.options:
            if 'value' in option and option['value'] == passphrase:
                del option['value']

        # we take a hit in message size when b64 encoding
        return dict(
            extension=extension,
            passphrase=passphrase,
            data=base64.b64encode(data).decode("utf-8"),
        )


class CertificateRevoke(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(certificate_revoke_schema, None)
    def put(self, certificate_id, data=None):
        """
        .. http:put:: /certificates/1/revoke

           Revoke a certificate. One can mention the reason of revocation using crlReason (optional) as per
           `RFC 5280 section 5.3.1 <https://tools.ietf.org/html/rfc5280#section-5.3.1>`_
           The allowed values for crlReason can also be found in Lemur in `constants.py/CRLReason <https://github.com/Netflix/lemur/blob/master/lemur/constants.py#L49>`_
           Additional information can be captured using comments (optional).

           **Example request**:

           .. sourcecode:: http

              PUT /certificates/1/revoke HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "crlReason": "affiliationChanged",
                "comments": "Additional details if any"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated or cert attached to LB
           :statuscode 400: encountered error, more details in error message

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to revoke this certificate."),
                    403,
                )

        if cert.endpoints:
            for endpoint in cert.endpoints:
                if service.is_attached_to_endpoint(cert.name, endpoint.name):
                    return (
                        dict(
                            message="Cannot revoke certificate. Endpoints are deployed with the given certificate."
                        ),
                        403,
                    )

        try:
            error_message = service.revoke(cert, data)
            log_service.create(g.current_user, "revoke_cert", certificate=cert)

            if error_message:
                return dict(message=f"Certificate (id:{cert.id}) is revoked - {error_message}"), 400
            return dict(id=cert.id)
        except NotImplementedError as ne:
            return dict(message="Revoke is not implemented for issuer of this certificate"), 400
        except Exception as e:
            capture_exception()
            return dict(message=f"Failed to revoke: {str(e)}"), 400


class CertificateDeactivate(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def put(self, certificate_id):
        """
        .. http:put:: /certificates/1/deactivate

           deactivate a certificate (integration test only)
           **Example request**:

           .. sourcecode:: http

              PUT /certificates/1/deactivate HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated or cert attached to LB
           :statuscode 400: encountered error, more details in error message

        """
        cert = service.get(certificate_id)

        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        # allow creators
        if g.current_user != cert.user:
            owner_role = role_service.get_by_name(cert.owner)
            permission = CertificatePermission(owner_role, [x.name for x in cert.roles])

            if not permission.can():
                return (
                    dict(message="You are not authorized to deactivate this certificate."),
                    403,
                )

        try:
            error_message = service.deactivate(cert)
            log_service.create(g.current_user, "deactivate_cert", certificate=cert)

            if error_message:
                return dict(message=f"Certificate (id:{cert.id}) is deactivated - {error_message}"), 400
            return dict(id=cert.id)
        except NotImplementedError as ne:
            return dict(message="Deactivate is not implemented for issuer of this certificate"), 400
        except Exception as e:
            capture_exception()
            return dict(message=f"Failed to Deactivate: {str(e)}"), 400


api.add_resource(
    CertificateDeactivate,
    "/certificates/<int:certificate_id>/deactivate",
    endpoint="deactivateCertificate",
)
api.add_resource(
    CertificateRevoke,
    "/certificates/<int:certificate_id>/revoke",
    endpoint="revokeCertificate",
)
api.add_resource(
    CertificatesNameQuery,
    "/certificates/name/<string:certificate_name>",
    endpoint="certificatesNameQuery",
)
api.add_resource(CertificatesList, "/certificates", endpoint="certificates")
api.add_resource(
    CertificatesListValid, "/certificates/valid", endpoint="certificatesListValid"
)
api.add_resource(
    Certificates, "/certificates/<int:certificate_id>", endpoint="certificate"
)
api.add_resource(
    Certificates, "/certificates/<int:certificate_id>/update/switches", endpoint="certificateUpdateSwitches"
)
api.add_resource(
    CertificateUpdateOwner, "/certificates/<int:certificate_id>/update/owner", endpoint="certificateUpdateOwner"
)
api.add_resource(CertificatesStats, "/certificates/stats", endpoint="certificateStats")
api.add_resource(
    CertificatesUpload, "/certificates/upload", endpoint="certificateUpload"
)
api.add_resource(
    CertificatePrivateKey,
    "/certificates/<int:certificate_id>/key",
    endpoint="privateKeyCertificates",
)
api.add_resource(
    CertificateExport,
    "/certificates/<int:certificate_id>/export",
    endpoint="exportCertificate",
)
api.add_resource(
    NotificationCertificatesList,
    "/notifications/<int:notification_id>/certificates",
    endpoint="notificationCertificates",
)
api.add_resource(
    CertificatesReplacementsList,
    "/certificates/<int:certificate_id>/replacements",
    endpoint="replacements",
)
