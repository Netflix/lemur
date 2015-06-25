"""
.. module: lemur.certificates.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint, make_response, jsonify
from flask.ext.restful import reqparse, Api, fields

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from lemur.certificates import service
from lemur.authorities.models import Authority

from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import ViewKeyPermission, AuthorityPermission, UpdateCertificatePermission

from lemur.roles import service as role_service

from lemur.common.utils import marshal_items, paginated_parser


mod = Blueprint('certificates', __name__)
api = Api(mod)


FIELDS = {
    'name': fields.String,
    'id': fields.Integer,
    'bits': fields.Integer,
    'deleted': fields.String,
    'issuer': fields.String,
    'serial': fields.String,
    'owner': fields.String,
    'chain': fields.String,
    'san': fields.String,
    'active': fields.Boolean,
    'description': fields.String,
    'notBefore': fields.DateTime(dt_format='iso8601', attribute='not_before'),
    'notAfter': fields.DateTime(dt_format='iso8601', attribute='not_after'),
    'cn': fields.String,
    'status': fields.String,
    'body': fields.String
}


def valid_authority(authority_options):
    """
    Defends against invalid authorities

    :param authority_name:
    :return: :raise ValueError:
    """
    name = authority_options['name']
    authority = Authority.query.filter(Authority.name == name).one()

    if not authority:
        raise ValueError("Unable to find authority specified")

    if not authority.active:
        raise ValueError("Selected authority [{0}] is not currently active".format(name))

    return authority


def pem_str(value, name):
    """
    Used to validate that the given string is a PEM formatted string

    :param value:
    :param name:
    :return: :raise ValueError:
    """
    try:
        x509.load_pem_x509_certificate(str(value), default_backend())
    except Exception as e:
        raise ValueError("The parameter '{0}' needs to be a valid PEM string".format(name))
    return value


def private_key_str(value, name):
    """
    User to validate that a given string is a RSA private key

    :param value:
    :param name:
    :return: :raise ValueError:
    """
    try:
        serialization.load_pem_private_key(str(value), None, backend=default_backend())
    except Exception as e:
        raise ValueError("The parameter '{0}' needs to be a valid RSA private key".format(name))
    return value



class CertificatesList(AuthenticatedResource):
    """ Defines the 'certificates' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesList, self).__init__()

    @marshal_items(FIELDS)
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
           :query filter: key value pair. format is k=v;
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
        parser.add_argument('accountId', type=int, dest="account_id", location='args')
        parser.add_argument('creator', type=str, location='args')
        parser.add_argument('show', type=str, location='args')

        args = parser.parse_args()
        return service.render(args)

    @marshal_items(FIELDS)
    def post(self):
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
                "validityEnd": "2015-06-16T07:00:00.000Z"
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
           :arg commonName: certiifcate common name
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        self.reqparse.add_argument('extensions', type=dict, location='json')
        self.reqparse.add_argument('accounts', type=list, location='json')
        self.reqparse.add_argument('elbs', type=list, location='json')
        self.reqparse.add_argument('owner', type=str, location='json')
        self.reqparse.add_argument('validityStart', type=str, location='json') # parse date
        self.reqparse.add_argument('validityEnd', type=str, location='json') # parse date
        self.reqparse.add_argument('authority', type=valid_authority, location='json')
        self.reqparse.add_argument('description', type=str, location='json')
        self.reqparse.add_argument('country', type=str, location='json')
        self.reqparse.add_argument('state', type=str, location='json')
        self.reqparse.add_argument('location', type=str, location='json')
        self.reqparse.add_argument('organization', type=str, location='json')
        self.reqparse.add_argument('organizationalUnit', type=str, location='json')
        self.reqparse.add_argument('owner', type=str, location='json')
        self.reqparse.add_argument('commonName', type=str, location='json')

        args = self.reqparse.parse_args()

        authority = args['authority']
        role = role_service.get_by_name(authority.owner)

        # all the authority role members should be allowed
        roles = [x.name for x in authority.roles]

        # allow "owner" roles by team DL
        roles.append(role)
        permission = AuthorityPermission(authority.id, roles)

        if permission.can():
            return service.create(**args)

        return dict(message="You are not authorized to use {0}".format(args['authority'].name)), 403


class CertificatesUpload(AuthenticatedResource):
    """ Defines the 'certificates' upload endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesUpload, self).__init__()

    @marshal_items(FIELDS)
    def post(self):
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
                 "accounts": []
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
                 "cn": "example.com",
                 "status": "unknown"
              }

           :arg owner: owner email for certificate
           :arg publicCert: valid PEM public key for certificate
           :arg intermediateCert valid PEM intermediate key for certificate
           :arg privateKey: valid PEM private key for certificate
           :arg accounts: list of aws accounts to upload the certificate to
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 403: unauthenticated
           :statuscode 200: no error
        """
        self.reqparse.add_argument('owner', type=str, required=True, location='json')
        self.reqparse.add_argument('publicCert', type=pem_str, required=True, dest='public_cert', location='json')
        self.reqparse.add_argument('accounts', type=list, dest='accounts', location='json')
        self.reqparse.add_argument('intermediateCert', type=pem_str, dest='intermediate_cert', location='json')
        self.reqparse.add_argument('privateKey', type=private_key_str, dest='private_key', location='json')

        args = self.reqparse.parse_args()
        if args.get('accounts'):
            if args.get('private_key'):
                return service.upload(**args)
            else:
                raise Exception("Private key must be provided in order to upload certificate to AWS")
        return service.upload(**args)


class CertificatesStats(AuthenticatedResource):
    """ Defines the 'certificates' stats endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificatesStats, self).__init__()

    def get(self):
        self.reqparse.add_argument('metric', type=str, location='args')
        self.reqparse.add_argument('range', default=32, type=int, location='args')
        self.reqparse.add_argument('accountId', dest='account_id', location='args')
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
        role = role_service.get_by_name(cert.owner)

        permission = ViewKeyPermission(certificate_id, hasattr(role, 'id'))

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

    @marshal_items(FIELDS)
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
                "cn": "example.com",
                "status": "unknown"
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(certificate_id)

    @marshal_items(FIELDS)
    def put(self, certificate_id):
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

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        self.reqparse.add_argument('active', type=bool, location='json')
        self.reqparse.add_argument('owner', type=str, location='json')
        args = self.reqparse.parse_args()

        cert = service.get(certificate_id)
        role = role_service.get_by_name(cert.owner)
        permission = UpdateCertificatePermission(certificate_id, hasattr(role, 'id'))

        if permission.can():
            return service.update(certificate_id, args['owner'], args['active'])

        return dict(message='You are not authorized to update this certificate'), 403


api.add_resource(CertificatesList, '/certificates', endpoint='certificates')
api.add_resource(Certificates, '/certificates/<int:certificate_id>', endpoint='certificate')
api.add_resource(CertificatesStats, '/certificates/stats', endpoint='certificateStats')
api.add_resource(CertificatesUpload, '/certificates/upload', endpoint='certificateUpload')
api.add_resource(CertificatePrivateKey, '/certificates/<int:certificate_id>/key', endpoint='privateKeyCertificates')
