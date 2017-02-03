"""
.. module: lemur.auth.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import jwt
import base64
import sys
import requests

from flask import Blueprint, current_app

from flask_restful import reqparse, Resource, Api
from flask_principal import Identity, identity_changed

from lemur.extensions import metrics
from lemur.common.utils import get_psuedo_random_string

from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.auth.service import create_token, fetch_token_header, get_rsa_public_key


mod = Blueprint('auth', __name__)
api = Api(mod)


class Login(Resource):
    """
    Provides an endpoint for Lemur's basic authentication. It takes a username and password
    combination and returns a JWT token.

    This token token is required for each API request and must be provided in the Authorization Header for the request.
    ::

        Authorization:Bearer <token>

    Tokens have a set expiration date. You can inspect the token expiration by base64 decoding the token and inspecting
    it's contents.

    .. note:: It is recommended that the token expiration is fairly short lived (hours not days). This will largely depend \
    on your uses cases but. It is important to not that there is currently no build in method to revoke a users token \
    and force re-authentication.
    """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Login, self).__init__()

    def post(self):
        """
        .. http:post:: /auth/login

           Login with username:password

           **Example request**:

           .. sourcecode:: http

              POST /auth/login HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript

              {
                "username": "test",
                "password": "test"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "token": "12343243243"
              }

           :arg username: username
           :arg password: password
           :statuscode 401: invalid credentials
           :statuscode 200: no error
        """
        self.reqparse.add_argument('username', type=str, required=True, location='json')
        self.reqparse.add_argument('password', type=str, required=True, location='json')

        args = self.reqparse.parse_args()

        if '@' in args['username']:
            user = user_service.get_by_email(args['username'])
        else:
            user = user_service.get_by_username(args['username'])

        if user and user.check_password(args['password']) and user.active:
            # Tell Flask-Principal the identity changed
            identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))

            metrics.send('successful_login', 'counter', 1)
            return dict(token=create_token(user))

        metrics.send('invalid_login', 'counter', 1)
        return dict(message='The supplied credentials are invalid'), 401


class Ping(Resource):
    """
    This class serves as an example of how one might implement an SSO provider for use with Lemur. In
    this example we use an OpenIDConnect authentication flow, that is essentially OAuth2 underneath. If you have an
    OAuth2 provider you want to use Lemur there would be two steps:

    1. Define your own class that inherits from :class:`flask.ext.restful.Resource` and create the HTTP methods the \
    provider uses for it's callbacks.
    2. Add or change the Lemur AngularJS Configuration to point to your new provider
    """
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Ping, self).__init__()

    def post(self):
        self.reqparse.add_argument('clientId', type=str, required=True, location='json')
        self.reqparse.add_argument('redirectUri', type=str, required=True, location='json')
        self.reqparse.add_argument('code', type=str, required=True, location='json')

        args = self.reqparse.parse_args()

        # take the information we have received from the provider to create a new request
        params = {
            'client_id': args['clientId'],
            'grant_type': 'authorization_code',
            'scope': 'openid email profile address',
            'redirect_uri': args['redirectUri'],
            'code': args['code']
        }

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get('PING_ACCESS_TOKEN_URL')
        user_api_url = current_app.config.get('PING_USER_API_URL')

        # the secret and cliendId will be given to you when you signup for the provider
        token = '{0}:{1}'.format(args['clientId'], current_app.config.get("PING_SECRET"))

        basic = base64.b64encode(bytes(token, 'utf-8'))
        headers = {'authorization': 'basic {0}'.format(basic.decode('utf-8'))}

        # exchange authorization code for access token.

        r = requests.post(access_token_url, headers=headers, params=params)
        id_token = r.json()['id_token']
        access_token = r.json()['access_token']

        # fetch token public key
        header_data = fetch_token_header(id_token)
        jwks_url = current_app.config.get('PING_JWKS_URL')

        # retrieve the key material as specified by the token header
        r = requests.get(jwks_url)
        for key in r.json()['keys']:
            if key['kid'] == header_data['kid']:
                secret = get_rsa_public_key(key['n'], key['e'])
                algo = header_data['alg']
                break
        else:
            return dict(message='Key not found'), 403

        # validate your token based on the key it was signed with
        try:
            jwt.decode(id_token, secret.decode('utf-8'), algorithms=[algo], audience=args['clientId'])
        except jwt.DecodeError:
            return dict(message='Token is invalid'), 403
        except jwt.ExpiredSignatureError:
            return dict(message='Token has expired'), 403
        except jwt.InvalidTokenError:
            return dict(message='Token is invalid'), 403

        user_params = dict(access_token=access_token, schema='profile')

        # retrieve information about the current user.
        r = requests.get(user_api_url, params=user_params)
        profile = r.json()

        user = user_service.get_by_email(profile['email'])
        metrics.send('successful_login', 'counter', 1)

        # update their google 'roles'
        roles = []

        for group in profile['googleGroups']:
            role = role_service.get_by_name(group)
            if not role:
                role = role_service.create(group, description='This is a google group based role created by Lemur')
            roles.append(role)

        role = role_service.get_by_name(profile['email'])

        if not role:
            role = role_service.create(profile['email'], description='This is a user specific role')
        roles.append(role)

        # if we get an sso user create them an account
        if not user:
            # every user is an operator (tied to a default role)
            if current_app.config.get('LEMUR_DEFAULT_ROLE'):
                v = role_service.get_by_name(current_app.config.get('LEMUR_DEFAULT_ROLE'))
                if v:
                    roles.append(v)

            user = user_service.create(
                profile['email'],
                get_psuedo_random_string(),
                profile['email'],
                True,
                profile.get('thumbnailPhotoUrl'),
                roles
            )

        else:
            # we add 'lemur' specific roles, so they do not get marked as removed
            for ur in user.roles:
                if ur.authority_id:
                    roles.append(ur)

            # update any changes to the user
            user_service.update(
                user.id,
                profile['email'],
                profile['email'],
                True,
                profile.get('thumbnailPhotoUrl'),  # incase profile isn't google+ enabled
                roles
            )

        if not user.active:
            metrics.send('invalid_login', 'counter', 1)
            return dict(message='The supplied credentials are invalid'), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

        metrics.send('successful_login', 'counter', 1)
        return dict(token=create_token(user))


class OAuth2(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(OAuth2, self).__init__()

    def post(self):
        self.reqparse.add_argument('clientId', type=str, required=True, location='json')
        self.reqparse.add_argument('redirectUri', type=str, required=True, location='json')
        self.reqparse.add_argument('code', type=str, required=True, location='json')

        args = self.reqparse.parse_args()

        # take the information we have received from the provider to create a new request
        params = {
            'grant_type': 'authorization_code',
            'scope': 'openid email profile groups',
            'redirect_uri': args['redirectUri'],
            'code': args['code'],
        }

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get('OAUTH2_ACCESS_TOKEN_URL')
        user_api_url = current_app.config.get('OAUTH2_USER_API_URL')

        # the secret and cliendId will be given to you when you signup for the provider
        token = '{0}:{1}'.format(args['clientId'], current_app.config.get("OAUTH2_SECRET"))

        basic = base64.b64encode(bytes(token, 'utf-8'))

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'authorization': 'basic {0}'.format(basic.decode('utf-8'))
        }

        # exchange authorization code for access token.
        r = requests.post(access_token_url, headers=headers, params=params)
        id_token = r.json()['id_token']
        access_token = r.json()['access_token']

        # fetch token public key
        header_data = fetch_token_header(id_token)
        jwks_url = current_app.config.get('OAUTH2_JWKS_URL')

        # retrieve the key material as specified by the token header
        r = requests.get(jwks_url)
        for key in r.json()['keys']:
            if key['kid'] == header_data['kid']:
                secret = get_rsa_public_key(key['n'], key['e'])
                algo = header_data['alg']
                break
        else:
            return dict(message='Key not found'), 403

        # validate your token based on the key it was signed with
        try:
            if sys.version_info >= (3, 0):
                jwt.decode(id_token, secret.decode('utf-8'), algorithms=[algo], audience=args['clientId'])
            else:
                jwt.decode(id_token, secret, algorithms=[algo], audience=args['clientId'])
        except jwt.DecodeError:
            return dict(message='Token is invalid'), 403
        except jwt.ExpiredSignatureError:
            return dict(message='Token has expired'), 403
        except jwt.InvalidTokenError:
            return dict(message='Token is invalid'), 403

        headers = {'authorization': 'Bearer {0}'.format(access_token)}

        # retrieve information about the current user.
        r = requests.get(user_api_url, headers=headers)
        profile = r.json()

        user = user_service.get_by_email(profile['email'])
        metrics.send('successful_login', 'counter', 1)

        # update their google 'roles'
        roles = []

        role = role_service.get_by_name(profile['email'])
        if not role:
            role = role_service.create(profile['email'], description='This is a user specific role')
        roles.append(role)

        # if we get an sso user create them an account
        if not user:
            # every user is an operator (tied to a default role)
            if current_app.config.get('LEMUR_DEFAULT_ROLE'):
                v = role_service.get_by_name(current_app.config.get('LEMUR_DEFAULT_ROLE'))
                if v:
                    roles.append(v)

            user = user_service.create(
                profile['name'],
                get_psuedo_random_string(),
                profile['email'],
                True,
                profile.get('thumbnailPhotoUrl'),
                roles
            )

        else:
            # we add 'lemur' specific roles, so they do not get marked as removed
            for ur in user.roles:
                if ur.authority_id:
                    roles.append(ur)

            # update any changes to the user
            user_service.update(
                user.id,
                profile['name'],
                profile['email'],
                True,
                profile.get('thumbnailPhotoUrl'),  # incase profile isn't google+ enabled
                roles
            )

        # Tell Flask-Principal the identity changed
        identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

        return dict(token=create_token(user))


class Google(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Google, self).__init__()

    def post(self):
        access_token_url = 'https://accounts.google.com/o/oauth2/token'
        people_api_url = 'https://www.googleapis.com/plus/v1/people/me/openIdConnect'

        self.reqparse.add_argument('clientId', type=str, required=True, location='json')
        self.reqparse.add_argument('redirectUri', type=str, required=True, location='json')
        self.reqparse.add_argument('code', type=str, required=True, location='json')

        args = self.reqparse.parse_args()

        # Step 1. Exchange authorization code for access token
        payload = {
            'client_id': args['clientId'],
            'grant_type': 'authorization_code',
            'redirect_uri': args['redirectUri'],
            'code': args['code'],
            'client_secret': current_app.config.get('GOOGLE_SECRET')
        }

        r = requests.post(access_token_url, data=payload)
        token = r.json()

        # Step 2. Retrieve information about the current user
        headers = {'Authorization': 'Bearer {0}'.format(token['access_token'])}

        r = requests.get(people_api_url, headers=headers)
        profile = r.json()

        user = user_service.get_by_email(profile['email'])

        if not user.active:
            metrics.send('invalid_login', 'counter', 1)
            return dict(message='The supplied credentials are invalid.'), 401

        if user:
            metrics.send('successful_login', 'counter', 1)
            return dict(token=create_token(user))

        metrics.send('invalid_login', 'counter', 1)


class Providers(Resource):
    def get(self):
        active_providers = []

        for provider in current_app.config.get("ACTIVE_PROVIDERS", []):
            provider = provider.lower()

            if provider == "google":
                active_providers.append({
                    'name': 'google',
                    'clientId': current_app.config.get("GOOGLE_CLIENT_ID"),
                    'url': api.url_for(Google)
                })

            elif provider == "ping":
                active_providers.append({
                    'name': current_app.config.get("PING_NAME"),
                    'url': current_app.config.get('PING_REDIRECT_URI'),
                    'redirectUri': current_app.config.get("PING_REDIRECT_URI"),
                    'clientId': current_app.config.get("PING_CLIENT_ID"),
                    'responseType': 'code',
                    'scope': ['openid', 'email', 'profile', 'address'],
                    'scopeDelimiter': ' ',
                    'authorizationEndpoint': current_app.config.get("PING_AUTH_ENDPOINT"),
                    'requiredUrlParams': ['scope'],
                    'type': '2.0'
                })

            elif provider == "oauth2":
                active_providers.append({
                    'name': current_app.config.get("OAUTH2_NAME"),
                    'url': current_app.config.get('OAUTH2_REDIRECT_URI'),
                    'redirectUri': current_app.config.get("OAUTH2_REDIRECT_URI"),
                    'clientId': current_app.config.get("OAUTH2_CLIENT_ID"),
                    'responseType': 'code',
                    'scope': ['openid', 'email', 'profile', 'groups'],
                    'scopeDelimiter': ' ',
                    'authorizationEndpoint': current_app.config.get("OAUTH2_AUTH_ENDPOINT"),
                    'requiredUrlParams': ['scope', 'state', 'nonce'],
                    'state': 'STATE',
                    'nonce': get_psuedo_random_string(),
                    'type': '2.0'
                })

        return active_providers


api.add_resource(Login, '/auth/login', endpoint='login')
api.add_resource(Ping, '/auth/ping', endpoint='ping')
api.add_resource(Google, '/auth/google', endpoint='google')
api.add_resource(OAuth2, '/auth/oauth2', endpoint='oauth2')
api.add_resource(Providers, '/auth/providers', endpoint='providers')
