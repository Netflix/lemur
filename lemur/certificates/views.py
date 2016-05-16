"""
.. module: lemur.certificates.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import base64
from builtins import str

from flask import Blueprint, make_response, jsonify
from flask.ext.restful import reqparse, Api

from lemur.common.schema import validate_schema
from lemur.common.utils import paginated_parser

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import ViewKeyPermission, AuthorityPermission, UpdateCertificatePermission

from lemur.certificates import service
from lemur.certificates.schemas import certificate_input_schema, certificate_output_schema, \
    certificate_upload_input_schema, certificates_output_schema, certificate_export_input_schema, certificate_edit_input_schema

from lemur.roles import service as role_service


mod = Blueprint('certificates', __name__)
api = Api(mod)


class CertificatesList(AuthenticatedResource):
    """ Defines the 'certificates' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesList, self).__init__()

    @validate_schema(None, certificates_output_schema)
    def get(self):
        """
        .. http:get:: /certificates

           The current list of certificates

           **Example request**:

           .. sourcecode:: http

              GET /certificates HTTP/1.1
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
                      "name": "cert1",
                      "description": "this is cert1",
                      "bits": 2048,
                      "deleted": false,
                      "issuer": "ExampeInc.",
                      "serial": "123450",
                      "chain": "-----Begin ...",
                      "body": "-----Begin ...",
                      "san": true,
                      "owner": 'bob@example.com",
                      "active": true,
                      "notBefore": "2015-06-05T17:09:39",
                      "notAfter": "2015-06-10T17:09:39",
                      "cn": "example.com",
                      "status": "unknown"
                    }
                  ]
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int. default is 1
           :query filter: key value pair format is k;v
           :query limit: limit number. default is 10
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

              {
                "country": "US",
                "state": "CA",
                "location": "A Place",
                "organization": "ExampleInc.",
                "organizationalUnit": "Operations",
                "owner": "bob@example.com",
                "description": "test",
                "selectedAuthority": "timetest2",
                "csr": "----BEGIN CERTIFICATE REQUEST-----...",
                "authority": {
                    "body": "-----BEGIN...",
                    "name": "timetest2",
                    "chain": "",
                    "notBefore": "2015-06-05T15:20:59",
                    "active": true,
                    "id": 50,
                    "notAfter": "2015-06-17T15:21:08",
                    "description": "dsfdsf"
                },
                "notifications": [
                    {
                      "description": "Default 30 day expiration notification",
                      "notificationOptions": [
                        {
                          "name": "interval",
                          "required": true,
                          "value": 30,
                          "helpMessage": "Number of days to be alert before expiration.",
                          "validation": "^\\d+$",
                          "type": "int"
                        },
                        {
                          "available": [
                            "days",
                            "weeks",
                            "months"
                          ],
                          "name": "unit",
                          "required": true,
                          "value": "days",
                          "helpMessage": "Interval unit",
                          "validation": "",
                          "type": "select"
                        },
                        {
                          "name": "recipients",
                          "required": true,
                          "value": "bob@example.com",
                          "helpMessage": "Comma delimited list of email addresses",
                          "validation": "^([\\w+-.%]+@[\\w-.]+\\.[A-Za-z]{2,4},?)+$",
                            "type": "str"
                          }
                        ],
                        "label": "DEFAULT_KGLISSON_30_DAY",
                        "pluginName": "email-notification",
                        "active": true,
                        "id": 7
                    }
                ],
                "extensions": {
                    "basicConstraints": {},
                    "keyUsage": {
                        "isCritical": true,
                        "useKeyEncipherment": true,
                        "useDigitalSignature": true
                    },
                    "extendedKeyUsage": {
                        "isCritical": true,
                        "useServerAuthentication": true
                    },
                    "subjectKeyIdentifier": {
                        "includeSKI": true
                    },
                    "subAltNames": {
                        "names": []
                    }
                },
                "commonName": "test",
                "validityStart": "2015-06-05T07:00:00.000Z",
                "validityEnd": "2015-06-16T07:00:00.000Z",
                "replacements": [
                    {'id': 123}
                ],
                "name": "TestCertificate"
             }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "cert1",
                "description": "this is cert1",
                "bits": 2048,
                "deleted": false,
                "issuer": "ExampeInc.",
                "serial": "123450",
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "san": true,
                "owner": "jimbob@example.com",
                "active": false,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39",
                "cn": "example.com",
                "status": "unknown"
              }

           :arg extensions: extensions to be used in the certificate
           :arg description: description for new certificate
           :arg owner: owner email
           :arg validityStart: when the certificate should start being valid
           :arg validityEnd: when the certificate should expire
           :arg authority: authority that should issue the certificate
           :arg country: country for the CSR
           :arg state: state for the CSR
           :arg location: location for the CSR
           :arg organization: organization for CSR
           :arg commonName: certificate common name
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        role = role_service.get_by_name(data['authority'].owner)

        # all the authority role members should be allowed
        roles = [x.name for x in data['authority'].roles]

        # allow "owner" roles by team DL
        roles.append(role)
        authority_permission = AuthorityPermission(data['authority'].id, roles)

        if authority_permission.can():
            return service.create(**data)

        return dict(message="You are not authorized to use {0}".format(data['authority'].name)), 403


class CertificatesUpload(AuthenticatedResource):
    """ Defines the 'certificates' upload endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesUpload, self).__init__()

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

              {
                 "owner": "joe@exmaple.com",
                 "publicCert": "---Begin Public...",
                 "intermediateCert": "---Begin Public...",
                 "privateKey": "---Begin Private..."
                 "destinations": [],
                 "notifications": [],
                 "replacements": [],
                 "name": "cert1"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                 "id": 1,
                 "name": "cert1",
                 "description": "this is cert1",
                 "bits": 2048,
                 "deleted": false,
                 "issuer": "ExampeInc.",
                 "serial": "123450",
                 "chain": "-----Begin ...",
                 "body": "-----Begin ...",
                 "san": true,
                 "owner": "joe@example.com",
                 "active": true,
                 "notBefore": "2015-06-05T17:09:39",
                 "notAfter": "2015-06-10T17:09:39",
                 "signingAlgorithm": "sha2"
                 "cn": "example.com",
                 "status": "unknown"
              }

           :arg owner: owner email for certificate
           :arg publicCert: valid PEM public key for certificate
           :arg intermediateCert valid PEM intermediate key for certificate
           :arg privateKey: valid PEM private key for certificate
           :arg destinations: list of aws destinations to upload the certificate to
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 403: unauthenticated
           :statuscode 200: no error
        """
        if data.get('destinations'):
            if data.get('private_key'):
                return service.upload(**data)
            else:
                raise Exception("Private key must be provided in order to upload certificate to AWS")
        return service.upload(**data)


class CertificatesStats(AuthenticatedResource):
    """ Defines the 'certificates' stats endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesStats, self).__init__()

    def get(self):
        self.reqparse.add_argument('metric', type=str, location='args')
        self.reqparse.add_argument('range', default=32, type=int, location='args')
        self.reqparse.add_argument('destinationId', dest='destination_id', location='args')
        self.reqparse.add_argument('active', type=str, default='true', location='args')

        args = self.reqparse.parse_args()

        items = service.stats(**args)
        return dict(items=items, total=len(items))


class CertificatePrivateKey(AuthenticatedResource):
    def __init__(self):
        super(CertificatePrivateKey, self).__init__()

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
                 "key": "----Begin ...",
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        cert = service.get(certificate_id)
        if not cert:
            return dict(message="Cannot find specified certificate"), 404

        role = role_service.get_by_name(cert.owner)

        permission = ViewKeyPermission(certificate_id, getattr(role, 'name', None))

        if permission.can():
            response = make_response(jsonify(key=cert.private_key), 200)
            response.headers['cache-control'] = 'private, max-age=0, no-cache, no-store'
            response.headers['pragma'] = 'no-cache'
            return response

        return dict(message='You are not authorized to view this key'), 403


class Certificates(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Certificates, self).__init__()

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
                "id": 1,
                "name": "cert1",
                "description": "this is cert1",
                "bits": 2048,
                "deleted": false,
                "issuer": "ExampeInc.",
                "serial": "123450",
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "san": true,
                "owner": "bob@example.com",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39",
                "signingAlgorithm": "sha2",
                "cn": "example.com",
                "status": "unknown"
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
                "id": 1,
                "name": "cert1",
                "description": "this is cert1",
                "bits": 2048,
                "deleted": false,
                "issuer": "ExampeInc.",
                "serial": "123450",
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "san": true,
                "owner": "jimbob@example.com",
                "active": false,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39",
                "cn": "example.com",
                "status": "unknown",
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        cert = service.get(certificate_id)
        role = role_service.get_by_name(cert.owner)

        permission = UpdateCertificatePermission(certificate_id, getattr(role, 'name', None))

        if permission.can():
            return service.update(
                certificate_id,
                data['owner'],
                data['description'],
                data['active'],
                data['destinations'],
                data['notifications'],
                data['replacements']
            )

        return dict(message='You are not authorized to update this certificate'), 403


class NotificationCertificatesList(AuthenticatedResource):
    """ Defines the 'certificates' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(NotificationCertificatesList, self).__init__()

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
                "items": [
                    {
                      "id": 1,
                      "name": "cert1",
                      "description": "this is cert1",
                      "bits": 2048,
                      "deleted": false,
                      "issuer": "ExampeInc.",
                      "serial": "123450",
                      "chain": "-----Begin ...",
                      "body": "-----Begin ...",
                      "san": true,
                      "owner": 'bob@example.com",
                      "active": true,
                      "notBefore": "2015-06-05T17:09:39",
                      "notAfter": "2015-06-10T17:09:39",
                      "signingAlgorithm": "sha2",
                      "cn": "example.com",
                      "status": "unknown"
                    }
                  ]
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: acs or desc
           :query page: int default is 1
           :query filter: key value pair format is k;v
           :query limit: limit number default is 10
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
        args['notification_id'] = notification_id
        return service.render(args)


class CertificatesReplacementsList(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesReplacementsList, self).__init__()

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

              [{
                "id": 1,
                "name": "cert1",
                "description": "this is cert1",
                "bits": 2048,
                "deleted": false,
                "issuer": "ExampeInc.",
                "serial": "123450",
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "san": true,
                "owner": "bob@example.com",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39",
                "signingAlgorithm": "sha2",
                "cn": "example.com",
                "status": "unknown"
              }]

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(certificate_id).replaces


class CertificateExport(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificateExport, self).__init__()

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
        role = role_service.get_by_name(cert.owner)
        permission = UpdateCertificatePermission(certificate_id, getattr(role, 'name', None))

        options = data['plugin']['plugin_options']
        plugin = data['plugin']['plugin_object']

        if plugin.requires_key:
            if permission.can():
                extension, passphrase, data = plugin.export(cert.body, cert.chain, cert.private_key, options)
            else:
                return dict(message='You are not authorized to export this certificate'), 403
        else:
            extension, passphrase, data = plugin.export(cert.body, cert.chain, cert.private_key, options)

        # we take a hit in message size when b64 encoding
        return dict(extension=extension, passphrase=passphrase, data=base64.b64encode(data))


api.add_resource(CertificatesList, '/certificates', endpoint='certificates')
api.add_resource(Certificates, '/certificates/<int:certificate_id>', endpoint='certificate')
api.add_resource(CertificatesStats, '/certificates/stats', endpoint='certificateStats')
api.add_resource(CertificatesUpload, '/certificates/upload', endpoint='certificateUpload')
api.add_resource(CertificatePrivateKey, '/certificates/<int:certificate_id>/key', endpoint='privateKeyCertificates')
api.add_resource(CertificateExport, '/certificates/<int:certificate_id>/export', endpoint='exportCertificate')
api.add_resource(NotificationCertificatesList, '/notifications/<int:notification_id>/certificates',
                 endpoint='notificationCertificates')
api.add_resource(CertificatesReplacementsList, '/certificates/<int:certificate_id>/replacements',
                 endpoint='replacements')
