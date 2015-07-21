"""
.. module: lemur.authorities.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint, g
from flask.ext.restful import reqparse, fields, Api

from lemur.authorities import service
from lemur.roles import service as role_service
from lemur.certificates import service as certificate_service
from lemur.auth.service import AuthenticatedResource

from lemur.auth.permissions import AuthorityPermission

from lemur.common.utils import paginated_parser, marshal_items


FIELDS = {
    'name': fields.String,
    'description': fields.String,
    'options': fields.Raw,
    'pluginName': fields.String,
    'body': fields.String,
    'chain': fields.String,
    'active': fields.Boolean,
    'notBefore': fields.DateTime(dt_format='iso8601', attribute='not_before'),
    'notAfter': fields.DateTime(dt_format='iso8601', attribute='not_after'),
    'id': fields.Integer,
}

mod = Blueprint('authorities', __name__)
api = Api(mod)


class AuthoritiesList(AuthenticatedResource):
    """ Defines the 'authorities' endpoint """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(AuthoritiesList, self).__init__()

    @marshal_items(FIELDS)
    def get(self):
        """
        .. http:get:: /authorities

           The current list of authorities

           **Example request**:

           .. sourcecode:: http

              GET /authorities HTTP/1.1
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
                      "name": "authority1",
                      "description": "this is authority1",
                      "pluginName": null,
                      "chain": "-----Begin ...",
                      "body": "-----Begin ...",
                      "active": true,
                      "notBefore": "2015-06-05T17:09:39",
                      "notAfter": "2015-06-10T17:09:39"
                      "options": null
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

           :note: this will only show certificates that the current user is authorized to use
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        return service.render(args)

    @marshal_items(FIELDS)
    def post(self):
        """
        .. http:post:: /authorities

           Create an authority

           **Example request**:

           .. sourcecode:: http

              POST /authorities HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "caDN": {
                  "country": "US",
                  "state": "CA",
                  "location": "A Location",
                  "organization": "ExampleInc",
                  "organizationalUnit": "Operations",
                  "commonName": "a common name"
                },
                "caType": "root",
                "caSigningAlgo": "sha256WithRSA",
                "caSensitivity": "medium",
                "keyType": "RSA2048",
                "pluginName": "cloudca",
                "validityStart": "2015-06-11T07:00:00.000Z",
                "validityEnd": "2015-06-13T07:00:00.000Z",
                "caName": "DoctestCA",
                "ownerEmail": "jimbob@example.com",
                "caDescription": "Example CA",
                "extensions": {
                  "subAltNames": {
                    "names": []
                  }
                },
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "authority1",
                "description": "this is authority1",
                "pluginName": null,
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39"
                "options": null
              }

           :arg caName: authority's name
           :arg caDescription: a sensible description about what the CA with be used for
           :arg ownerEmail: the team or person who 'owns' this authority
           :arg validityStart: when this authority should start issuing certificates
           :arg validityEnd: when this authority should stop issuing certificates
           :arg extensions: certificate extensions
           :arg pluginName: name of the plugin to create the authority
           :arg caType: the type of authority (root/subca)
           :arg caParent: the parent authority if this is to be a subca
           :arg caSigningAlgo: algorithm used to sign the authority
           :arg keyType: key type
           :arg caSensitivity: the sensitivity of the root key, for CloudCA this determines if the root keys are stored
           in an HSM
           :arg caKeyName: name of the key to store in the HSM (CloudCA)
           :arg caSerialNumber: serial number of the authority
           :arg caFirstSerial: specifies the starting serial number for certificates issued off of this authority
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 403: unauthenticated
           :statuscode 200: no error
        """
        self.reqparse.add_argument('caName', type=str, location='json', required=True)
        self.reqparse.add_argument('caDescription', type=str, location='json', required=False)
        self.reqparse.add_argument('ownerEmail', type=str, location='json', required=True)
        self.reqparse.add_argument('caDN', type=dict, location='json', required=False)
        self.reqparse.add_argument('validityStart', type=str, location='json', required=False)  # TODO validate
        self.reqparse.add_argument('validityEnd', type=str, location='json', required=False)  # TODO validate
        self.reqparse.add_argument('extensions', type=dict, location='json', required=False)
        self.reqparse.add_argument('pluginName', type=str, location='json', required=True)
        self.reqparse.add_argument('caType', type=str, location='json', required=False)
        self.reqparse.add_argument('caParent', type=str, location='json', required=False)
        self.reqparse.add_argument('caSigningAlgo', type=str, location='json', required=False)
        self.reqparse.add_argument('keyType', type=str, location='json', required=False)
        self.reqparse.add_argument('caSensitivity', type=str, location='json', required=False)
        self.reqparse.add_argument('caKeyName', type=str, location='json', required=False)
        self.reqparse.add_argument('caSerialNumber', type=int, location='json', required=False)
        self.reqparse.add_argument('caFirstSerial', type=int, location='json', required=False)

        args = self.reqparse.parse_args()
        return service.create(args)


class Authorities(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Authorities, self).__init__()

    @marshal_items(FIELDS)
    def get(self, authority_id):
        """
        .. http:get:: /authorities/1

           One authority

           **Example request**:

           .. sourcecode:: http

              GET /authorities/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "authority1",
                "description": "this is authority1",
                "pluginName": null,
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39"
                "options": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(authority_id)

    @marshal_items(FIELDS)
    def put(self, authority_id):
        """
        .. http:put:: /authorities/1

           Update a authority

           **Example request**:

           .. sourcecode:: http

              PUT /authorities/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                 "roles": [],
                 "active": false
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "authority1",
                "description": "this is authority1",
                "pluginname": null,
                "chain": "-----begin ...",
                "body": "-----begin ...",
                "active": false,
                "notbefore": "2015-06-05t17:09:39",
                "notafter": "2015-06-10t17:09:39"
                "options": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        self.reqparse.add_argument('roles', type=list, location='json')
        self.reqparse.add_argument('active', type=str, location='json')
        args = self.reqparse.parse_args()

        authority = service.get(authority_id)
        role = role_service.get_by_name(authority.owner)

        # all the authority role members should be allowed
        roles = [x.name for x in authority.roles]

        # allow "owner" roles by team DL
        roles.append(role)
        permission = AuthorityPermission(authority_id, roles)

        # we want to make sure that we cannot add roles that we are not members of
        if not g.current_user.is_admin:
            role_ids = set([r['id'] for r in args['roles']])
            user_role_ids = set([r.id for r in g.current_user.roles])

            if not role_ids.issubset(user_role_ids):
                return dict(message="You are not allowed to associate a role which you are not a member of"), 400

        if permission.can():
            return service.update(authority_id, active=args['active'], roles=args['roles'])

        return dict(message="You are not authorized to update this authority"), 403


class CertificateAuthority(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(CertificateAuthority, self).__init__()

    @marshal_items(FIELDS)
    def get(self, certificate_id):
        """
        .. http:get:: /certificates/1/authority

           One authority for given certificate

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/authority HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "id": 1,
                "name": "authority1",
                "description": "this is authority1",
                "pluginName": null,
                "chain": "-----Begin ...",
                "body": "-----Begin ...",
                "active": true,
                "notBefore": "2015-06-05T17:09:39",
                "notAfter": "2015-06-10T17:09:39"
                "options": null
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        cert = certificate_service.get(certificate_id)
        if not cert:
            return dict(message="Certificate not found"), 404

        return cert.authority

api.add_resource(AuthoritiesList, '/authorities', endpoint='authorities')
api.add_resource(Authorities, '/authorities/<int:authority_id>', endpoint='authority')
api.add_resource(CertificateAuthority, '/certificates/<int:certificate_id>/authority', endpoint='certificateAuthority')
