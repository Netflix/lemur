"""
.. module: lemur.authorities.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint, g
from flask_restful import reqparse, Api

from lemur.common import validators
from lemur.common.utils import paginated_parser
from lemur.common.schema import validate_schema
from lemur.auth.service import AuthenticatedResource
from lemur.auth.permissions import AuthorityCreatorPermission, AuthorityPermission, StrictRolePermission

from lemur.certificates import service as certificate_service

from lemur.authorities import service
from lemur.authorities.schemas import (
    authority_input_schema,
    authority_output_schema,
    authorities_output_schema,
    authority_update_schema,
)


mod = Blueprint("authorities", __name__)
api = Api(mod)


class AuthoritiesList(AuthenticatedResource):
    """ Defines the 'authorities' endpoint """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, authorities_output_schema)
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
                "items": [{
                    "name": "TestAuthority",
                    "roles": [{
                        "id": 123,
                        "name": "secure@example.com"
                    }, {
                        "id": 564,
                        "name": "TestAuthority_admin"
                    }, {
                        "id": 565,
                        "name": "TestAuthority_operator"
                    }],
                    "options": null,
                    "active": true,
                    "authorityCertificate": {
                        "body": "-----BEGIN CERTIFICATE-----IyMzU5MTVaMHk...",
                        "status": true,
                        "cn": "AcommonName",
                        "description": "This is the ROOT certificate for the TestAuthority certificate authority.",
                        "chain": "",
                        "notBefore": "2016-06-02T00:00:15+00:00",
                        "notAfter": "2023-06-02T23:59:15+00:00",
                        "owner": "secure@example.com",
                        "user": {
                            "username": "joe@example.com",
                            "active": true,
                            "email": "joe@example.com",
                            "id": 3
                        },
                        "active": true,
                        "bits": 2048,
                        "id": 2235,
                        "name": "TestAuthority"
                    },
                    "owner": "secure@example.com",
                    "id": 43,
                    "description": "This is the ROOT certificate for the TestAuthority certificate authority."
                }],
                "total": 1
              }

           :query sortBy: field to sort on
           :query sortDir: asc or desc
           :query page: int default is 1
           :query filter: key value pair. format is k;v
           :query count: count number default is 10
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated

           :note: this will only show certificates that the current user is authorized to use
        """
        parser = paginated_parser.copy()
        args = parser.parse_args()
        args["user"] = g.current_user
        return service.render(args)

    @validate_schema(authority_input_schema, authority_output_schema)
    def post(self, data=None):
        """
        .. http:post:: /authorities

           Create an authority

           **Example request**:

           .. sourcecode:: http

              POST /authorities HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                 "country": "US",
                 "state": "California",
                 "location": "Los Gatos",
                 "organization": "Netflix",
                 "organizationalUnit": "Operations",
                 "type": "root",
                 "signingAlgorithm": "sha256WithRSA",
                 "sensitivity": "medium",
                 "keyType": "RSA2048",
                 "plugin": {
                     "slug": "cloudca-issuer"
                 },
                 "name": "TimeTestAuthority5",
                 "owner": "secure@example.com",
                 "description": "test",
                 "commonName": "AcommonName",
                 "validityYears": "20",
                 "extensions": {
                     "subAltNames": {
                         "names": []
                     },
                     "custom": []
                 }
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "name": "TestAuthority",
                "roles": [{
                    "id": 123,
                    "name": "secure@example.com"
                }, {
                    "id": 564,
                    "name": "TestAuthority_admin"
                }, {
                    "id": 565,
                    "name": "TestAuthority_operator"
                }],
                "options": null,
                "active": true,
                "authorityCertificate": {
                    "body": "-----BEGIN CERTIFICATE-----IyMzU5MTVaMHk...",
                    "status": true,
                    "cn": "AcommonName",
                    "description": "This is the ROOT certificate for the TestAuthority certificate authority.",
                    "chain": "",
                    "notBefore": "2016-06-02T00:00:15+00:00",
                    "notAfter": "2023-06-02T23:59:15+00:00",
                    "owner": "secure@example.com",
                    "user": {
                        "username": "joe@example.com",
                        "active": true,
                        "email": "joe@example.com",
                        "id": 3
                    },
                    "active": true,
                    "bits": 2048,
                    "id": 2235,
                    "name": "TestAuthority"
                },
                "owner": "secure@example.com",
                "id": 43,
                "description": "This is the ROOT certificate for the TestAuthority certificate authority."
              }


           :arg name: authority's name
           :arg description: a sensible description about what the CA with be used for
           :arg owner: the team or person who 'owns' this authority
           :arg validityStart: when this authority should start issuing certificates
           :arg validityEnd: when this authority should stop issuing certificates
           :arg validityYears: starting from `now` how many years into the future the authority should be valid
           :arg extensions: certificate extensions
           :arg plugin: name of the plugin to create the authority
           :arg type: the type of authority (root/subca)
           :arg parent: the parent authority if this is to be a subca
           :arg signingAlgorithm: algorithm used to sign the authority
           :arg keyType: key type
           :arg sensitivity: the sensitivity of the root key, for CloudCA this determines if the root keys are stored in an HSM
           :arg keyName: name of the key to store in the HSM (CloudCA)
           :arg serialNumber: serial number of the authority
           :arg firstSerial: specifies the starting serial number for certificates issued off of this authority
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 401: unauthenticated
           :statuscode 403: unauthorized
           :statuscode 200: no error
        """
        permission = AuthorityCreatorPermission()
        if not permission.can() or not StrictRolePermission().can():
            return dict(message="You are not allowed to create a new authority."), 403

        if not validators.is_valid_owner(data["owner"]):
            return dict(message=f"Invalid owner: check if {data['owner']} is a valid group email. Individuals cannot "
                                f"be authority owners."), 412

        data["creator"] = g.current_user
        return service.create(**data)


class Authorities(AuthenticatedResource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    @validate_schema(None, authority_output_schema)
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
                "roles": [{
                    "id": 123,
                    "name": "secure@example.com"
                }, {
                    "id": 564,
                    "name": "TestAuthority_admin"
                }, {
                    "id": 565,
                    "name": "TestAuthority_operator"
                }],
                "active": true,
                "owner": "secure@example.com",
                "id": 43,
                "description": "This is the ROOT certificate for the TestAuthority certificate authority."
              }

           :arg description: a sensible description about what the CA with be used for
           :arg owner: the team or person who 'owns' this authority
           :arg active: set whether this authoritity is currently in use
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 403: unauthenticated
           :statuscode 200: no error
           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        return service.get(authority_id)

    @validate_schema(authority_update_schema, authority_output_schema)
    def put(self, authority_id, data=None):
        """
        .. http:put:: /authorities/1

           Update an authority

           **Example request**:

           .. sourcecode:: http

              PUT /authorities/1 HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "name": "TestAuthority5",
                "roles": [{
                    "id": 566,
                    "name": "TestAuthority5_admin"
                }, {
                    "id": 567,
                    "name": "TestAuthority5_operator"
                }, {
                    "id": 123,
                    "name": "secure@example.com"
                }],
                "active": true,
                "authorityCertificate": {
                    "body": "-----BEGIN CERTIFICATE-----",
                    "status": null,
                    "cn": "AcommonName",
                    "description": "This is the ROOT certificate for the TestAuthority5 certificate authority.",
                    "chain": "",
                    "notBefore": "2016-06-03T00:00:51+00:00",
                    "notAfter": "2036-06-03T23:59:51+00:00",
                    "owner": "secure@example.com",
                    "user": {
                        "username": "joe@example.com",
                        "active": true,
                        "email": "joe@example.com",
                        "id": 3
                    },
                    "active": true,
                    "bits": 2048,
                    "id": 2280,
                    "name": "TestAuthority5"
                },
                "owner": "secure@example.com",
                "id": 44,
                "description": "This is the ROOT certificate for the TestAuthority5 certificate authority."
               }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "name": "TestAuthority",
                "roles": [{
                    "id": 123,
                    "name": "secure@example.com"
                }, {
                    "id": 564,
                    "name": "TestAuthority_admin"
                }, {
                    "id": 565,
                    "name": "TestAuthority_operator"
                }],
                "options": null,
                "active": true,
                "authorityCertificate": {
                    "body": "-----BEGIN CERTIFICATE-----IyMzU5MTVaMHk...",
                    "status": true,
                    "cn": "AcommonName",
                    "description": "This is the ROOT certificate for the TestAuthority certificate authority.",
                    "chain": "",
                    "notBefore": "2016-06-02T00:00:15+00:00",
                    "notAfter": "2023-06-02T23:59:15+00:00",
                    "owner": "secure@example.com",
                    "user": {
                        "username": "joe@example.com",
                        "active": true,
                        "email": "joe@example.com",
                        "id": 3
                    },
                    "active": true,
                    "bits": 2048,
                    "id": 2235,
                    "name": "TestAuthority"
                },
                "owner": "secure@example.com",
                "id": 43,
                "description": "This is the ROOT certificate for the TestAuthority certificate authority."
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        authority = service.get(authority_id)

        if not authority:
            return dict(message="Not Found"), 404

        # all the authority role members should be allowed
        roles = [x.name for x in authority.roles]
        permission = AuthorityPermission(authority_id, roles)

        if not permission.can() or not StrictRolePermission().can():
            return dict(message="You are not authorized to update this authority."), 403

        return service.update(
            authority_id,
            owner=data["owner"],
            description=data["description"],
            active=data["active"],
            roles=data["roles"],
            options=data.get("options")
        )


class CertificateAuthority(AuthenticatedResource):
    def __init__(self):
        super().__init__()

    @validate_schema(None, authority_output_schema)
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
                "name": "TestAuthority",
                "roles": [{
                    "id": 123,
                    "name": "secure@example.com"
                }, {
                    "id": 564,
                    "name": "TestAuthority_admin"
                }, {
                    "id": 565,
                    "name": "TestAuthority_operator"
                }],
                "options": null,
                "active": true,
                "authorityCertificate": {
                    "body": "-----BEGIN CERTIFICATE-----IyMzU5MTVaMHk...",
                    "status": true,
                    "cn": "AcommonName",
                    "description": "This is the ROOT certificate for the TestAuthority certificate authority.",
                    "chain": "",
                    "notBefore": "2016-06-02T00:00:15+00:00",
                    "notAfter": "2023-06-02T23:59:15+00:00",
                    "owner": "secure@example.com",
                    "user": {
                        "username": "joe@example.com",
                        "active": true,
                        "email": "joe@example.com",
                        "id": 3
                    },
                    "active": true,
                    "bits": 2048,
                    "id": 2235,
                    "name": "TestAuthority"
                },
                "owner": "secure@example.com",
                "id": 43,
                "description": "This is the ROOT certificate for the TestAuthority certificate authority."
              }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        cert = certificate_service.get(certificate_id)
        if not cert:
            return dict(message="Certificate not found."), 404

        return cert.authority


class AuthorityVisualizations(AuthenticatedResource):
    def get(self, authority_id):
        """
        .. http:get:: /authorities/1/visualize

           Authority visualization

           **Example request**:

           .. sourcecode:: http

              GET /certificates/1/visualize HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

                {"name": "flare",
                    "children": [
                        {
                            "name": "analytics",
                            "children": [
                                {
                                    "name": "cluster",
                                    "children": [
                                        {"name": "AgglomerativeCluster", "size": 3938},
                                        {"name": "CommunityStructure", "size": 3812},
                                        {"name": "HierarchicalCluster", "size": 6714},
                                        {"name": "MergeEdge", "size": 743}
                                    ]
                                }
                            ]
                        }
                    ]
                }

           :reqheader Authorization: OAuth token to authenticate
           :statuscode 200: no error
           :statuscode 403: unauthenticated
        """
        authority = service.get(authority_id)
        return dict(
            name=authority.name,
            children=[{"name": c.name} for c in authority.certificates],
        )


api.add_resource(AuthoritiesList, "/authorities", endpoint="authorities")
api.add_resource(Authorities, "/authorities/<int:authority_id>", endpoint="authority")
api.add_resource(
    AuthorityVisualizations,
    "/authorities/<int:authority_id>/visualize",
    endpoint="authority_visualizations",
)
api.add_resource(
    CertificateAuthority,
    "/certificates/<int:certificate_id>/authority",
    endpoint="certificateAuthority",
)
