"""
.. module: lemur.auth.service
    :platform: Unix
    :synopsis: This module contains all of the authentication duties for
    lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import jwt
import json
import base64
import binascii
from functools import wraps
from datetime import datetime, timedelta

from flask import g, current_app, jsonify, request

from flask.ext.restful import Resource
from flask.ext.principal import identity_loaded, RoleNeed, UserNeed

from flask.ext.principal import Identity, identity_changed

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from lemur.users import service as user_service
from lemur.auth.permissions import CertificateOwnerNeed, CertificateCreatorNeed, \
    AuthorityCreatorNeed, AuthorityOwnerNeed, ViewRoleCredentialsNeed


def base64url_decode(data):
    if isinstance(data, unicode):
        data = str(data)

    rem = len(data) % 4

    if rem > 0:
        data += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(data)


def base64url_encode(data):
    return base64.urlsafe_b64encode(data).replace(b'=', b'')


def get_rsa_public_key(n, e):
    """
    Retrieve an RSA public key based on a module and exponent as provided by the JWKS format.

    :param n:
    :param e:
    :return: a RSA Public Key in PEM format
    """
    n = int(binascii.hexlify(base64url_decode(n)), 16)
    e = int(binascii.hexlify(base64url_decode(e)), 16)
    pub = RSAPublicNumbers(e, n).public_key(default_backend())
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def create_token(user):
    """
    Create a valid JWT for a given user, this token is then used to authenticate
    sessions until the token expires.

    :param user:
    :return:
    """
    expiration_delta = timedelta(days=int(current_app.config.get('TOKEN_EXPIRATION', 1)))
    payload = {
        'sub': user.id,
        'iat': datetime.now(),
        'exp': datetime.now() + expiration_delta
    }
    token = jwt.encode(payload, current_app.config['TOKEN_SECRET'])
    return token.decode('unicode_escape')


def login_required(f):
    """
    Validates the JWT and ensures that is has not expired.

    :param f:
    :return:
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.headers.get('Authorization'):
            response = jsonify(message='Missing authorization header')
            response.status_code = 401
            return response

        token = request.headers.get('Authorization').split()[1]

        try:
            payload = jwt.decode(token, current_app.config['TOKEN_SECRET'])
        except jwt.DecodeError:
            return dict(message='Token is invalid'), 403
        except jwt.ExpiredSignatureError:
            return dict(message='Token has expired'), 403
        except jwt.InvalidTokenError:
            return dict(message='Token is invalid'), 403

        g.current_user = user_service.get(payload['sub'])

        if not g.current_user.id:
            return dict(message='You are not logged in'), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(current_app._get_current_object(), identity=Identity(g.current_user.id))

        return f(*args, **kwargs)

    return decorated_function


def fetch_token_header(token):
    """
    Fetch the header out of the JWT token.

    :param token:
    :return: :raise jwt.DecodeError:
    """
    token = token.encode('utf-8')
    try:
        signing_input, crypto_segment = token.rsplit(b'.', 1)
        header_segment, payload_segment = signing_input.split(b'.', 1)
    except ValueError:
        raise jwt.DecodeError('Not enough segments')

    try:
        return json.loads(base64url_decode(header_segment))
    except TypeError, binascii.Error:
        raise jwt.DecodeError('Invalid header padding')



@identity_loaded.connect
def on_identity_loaded(sender, identity):
    """
    Sets the identity of a given option, assigns additional permissions based on
    the role that the user is a part of.

    :param sender:
    :param identity:
    """
    # load the user
    user = user_service.get(identity.id)

    # add the UserNeed to the identity
    identity.provides.add(UserNeed(identity.id))

    # identity with the roles that the user provides
    if hasattr(user, 'roles'):
        for role in user.roles:
            identity.provides.add(CertificateOwnerNeed(unicode(role.id)))
            identity.provides.add(ViewRoleCredentialsNeed(unicode(role.id)))
            identity.provides.add(RoleNeed(role.name))

    # apply ownership for authorities
    if hasattr(user, 'authorities'):
        for authority in user.authorities:
            identity.provides.add(AuthorityCreatorNeed(unicode(authority.id)))

    # apply ownership of certificates
    if hasattr(user, 'certificates'):
        for certificate in user.certificates:
            identity.provides.add(CertificateCreatorNeed(unicode(certificate.id)))

    g.user = user


class AuthenticatedResource(Resource):
    """
    Inherited by all resources that need to be protected by authentication.
    """
    method_decorators = [login_required]

    def __init__(self):
        super(AuthenticatedResource, self).__init__()


