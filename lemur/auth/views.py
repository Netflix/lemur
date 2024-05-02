"""
.. module: lemur.auth.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from __future__ import annotations  # Import annotations to make type hints backwards compatible with Python 3.7/3.8

import base64
import time

import jwt
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from flask import Blueprint, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_principal import Identity, identity_changed
from flask_restful import reqparse, Resource, Api

from lemur.auth import ldap
from lemur.auth.service import create_token, fetch_token_header, get_rsa_public_key
from lemur.common.utils import get_psuedo_random_string, get_state_token_secret
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.exceptions import TokenExchangeFailed
from lemur.extensions import metrics
from lemur.logs import service as log_service
from lemur.plugins.base import plugins
from lemur.roles import service as role_service
from lemur.users import service as user_service

mod = Blueprint("auth", __name__)
api = Api(mod)
limiter = Limiter(app=current_app, key_func=get_remote_address)


def exchange_for_access_token(
    code, redirect_uri, client_id, secret, access_token_url=None, verify_cert=True
):
    """
    Exchanges authorization code for access token.

    :param code:
    :param redirect_uri:
    :param client_id:
    :param secret:
    :param access_token_url:
    :param verify_cert:
    :return:
    :return:
    """
    # take the information we have received from the provider to create a new request
    params = {
        "grant_type": "authorization_code",
        "scope": "openid email profile address",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }

    # the secret and cliendId will be given to you when you signup for the provider
    token = f"{client_id}:{secret}"

    basic = base64.b64encode(bytes(token, "utf-8"))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if current_app.config.get("TOKEN_AUTH_HEADER_CASE_SENSITIVE"):
        headers["Authorization"] = "Basic {}".format(basic.decode("utf-8"))
    else:
        headers["authorization"] = "basic {}".format(basic.decode("utf-8"))

    # exchange authorization code for access token.
    r = requests.post(
        access_token_url, headers=headers, params=params, verify=verify_cert
    )
    if r.status_code == 400:
        r = requests.post(
            access_token_url, headers=headers, data=params, verify=verify_cert
        )

    response = r.json()

    if not r.ok or "error" in response:
        raise TokenExchangeFailed(response.get("error", "Unknown error"), response.get("error_description", ""))

    id_token = response.get("id_token")
    access_token = response.get("access_token")

    if id_token is None or access_token is None:
        error = "missing tokens"
        missing_tokens = []
        if id_token is None:
            missing_tokens.append("id_token is missing")
        if access_token is None:
            missing_tokens.append("access_token is missing")
        description = " and ".join(missing_tokens)
        raise TokenExchangeFailed(error, description)

    return id_token, access_token


def validate_id_token(id_token, client_id, jwks_url):
    """
    Ensures that the token we receive is valid.

    :param id_token:
    :param client_id:
    :param jwks_url:
    :return:
    """
    # fetch token public key
    header_data = fetch_token_header(id_token)

    # retrieve the key material as specified by the token header
    r = requests.get(jwks_url)
    for key in r.json()["keys"]:
        if key["kid"] == header_data["kid"]:
            secret = get_rsa_public_key(key["n"], key["e"])
            algo = header_data["alg"]
            break
    else:
        return dict(message="Key not found"), 401

    # validate your token based on the key it was signed with
    try:
        jwt.decode(
            id_token, secret.decode("utf-8"), algorithms=[algo], audience=client_id
        )
    except jwt.DecodeError:
        return dict(message="Token is invalid"), 401
    except jwt.ExpiredSignatureError:
        return dict(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return dict(message="Token is invalid"), 401


def retrieve_user(user_api_url, access_token):
    """
    Fetch user information from provided user api_url.

    :param user_api_url:
    :param access_token:
    :return:
    """
    user_params = dict(access_token=access_token, schema="profile")

    headers = {}

    if current_app.config.get("PING_INCLUDE_BEARER_TOKEN"):
        headers = {"Authorization": f"Bearer {access_token}"}

    # retrieve information about the current user.
    r = requests.get(user_api_url, params=user_params, headers=headers)
    # Some IDPs, like "Keycloak", require a POST instead of a GET
    if r.status_code == 400:
        if current_app.config.get("PING_EXCLUDE_USER_PARAMS", False):
            r = requests.post(user_api_url, headers=headers)
        else:
            r = requests.post(user_api_url, data=user_params, headers=headers)

    profile = r.json()

    user = user_service.get_by_email(profile["email"])
    return user, profile


def retrieve_user_memberships(user_api_url, user_membership_provider, access_token):
    user, profile = retrieve_user(user_api_url, access_token)

    if user_membership_provider is None:
        return user, profile
    """
    Unaware of the usage of this code across the community, current implementation is config driven.
    Without USER_MEMBERSHIP_PROVIDER configured, it is backward compatible. Please define a plugin
    for custom implementation.
    """
    membership_provider = plugins.get(user_membership_provider)
    user_membership = {"email": profile["email"],
                       "thumbnailPhotoUrl": profile["thumbnailPhotoUrl"],
                       "googleGroups": membership_provider.retrieve_user_memberships(profile["userId"])}

    return user, user_membership


def create_user_roles(profile: dict) -> list[str]:
    """
    Generate a list of Lemur role names based on the provided user profile.

    The function maps the user's roles from the identity provider to corresponding roles in Lemur,
    creates roles dynamically based on the profile data, and assigns a unique role for each user.

    :param profile: A dictionary containing user information, including roles/groups from the identity provider.
    :return: A list of Lemur role names corresponding to the provided user profile.
    """
    roles = []

    # We default to pulling in "googleGroups" as that was historically hard coded
    idp_groups_keys = current_app.config.get("IDP_GROUPS_KEYS", ["googleGroups"])

    if isinstance(idp_groups_keys, str):
        idp_groups_keys = [idp_groups_keys]

    for idp_groups_key in idp_groups_keys:
        if idp_groups_key not in profile:
            current_app.logger.warning(
                f"""'{idp_groups_key}' not sent by identity provider for user {profile["email"]}."""
            )
            continue

        if not isinstance(profile[idp_groups_key], list) and all(isinstance(item, str) for item in profile[idp_groups_key]):
            # Catch instances where roles are not a list of strings
            current_app.logger.warning(
                f"""'{idp_groups_key}' sent by identity provider for user {profile["email"]} is not a list of strings."""
            )
            continue

        # Take a fixed set of groups/roles and map it to Lemur roles.
        # If the IDP_GROUPS_TO_ROLES is empty or not set, nothing happens.
        idp_group_to_role_map = current_app.config.get("IDP_ROLES_MAPPING", {})
        matched_roles = [
            idp_group_to_role_map[role] for role in profile.get(idp_groups_key, []) if role in idp_group_to_role_map
        ]
        roles.extend(matched_roles)

        # Automatically create and assign roles from the user profile.
        if current_app.config.get("IDP_ASSIGN_ROLES_FROM_USER_GROUPS", True):
            idp_roles_description = current_app.config.get("IDP_ROLES_DESCRIPTION",
                                                           f"Identity provider role from '{idp_groups_key}' (generated by Lemur)")
            idp_roles_prefix = current_app.config.get("IDP_ROLES_PREFIX", "")
            idp_roles_suffix = current_app.config.get("IDP_ROLES_SUFFIX", "")
            for group in profile.get(idp_groups_key, []):
                if group in ["admin", "operator", "read-only"] and current_app.config.get("IDP_PROTECT_BUILTINS", True):
                    current_app.logger.warning(
                        f"""Attempted to assign built in '{group}' to user {profile["email"]}. Group not assigned.""")
                    continue

                # Check if the group matches naming conventions
                if group.startswith(idp_roles_prefix) and group.endswith(idp_roles_suffix):
                    # Get the role from Lemur if it already exists
                    role = role_service.get_by_name(group)

                    if not role and current_app.config.get("IDP_CREATE_ROLES_FROM_USER_GROUPS", True):
                        current_app.logger.debug(
                            f"""Role '{group}' does not exist. Creating role from user {profile["email"]}""")
                        role = role_service.create(
                            group,
                            description=idp_roles_description,
                            third_party=True,
                        )

                    if role:
                        roles.append(role)

    # Create a unique role for each user. This is a kludge in order to assign a specific user to a specific cert
    # Defaults to enabled as this was previous/existing behavior
    if current_app.config.get("IDP_CREATE_PER_USER_ROLE", True):
        role = role_service.get_by_name(profile["email"])

        if not role:
            current_app.logger.debug(
                f"""Role '{profile["email"]}' does not exist. Creating role from user {profile["email"]}""")
            role = role_service.create(
                profile["email"],
                description="This is a user specific role",
                third_party=True,
            )

        roles.append(role)

    # every user is a <default> (ties user to a default role, the default configuration is operator)
    if current_app.config.get("LEMUR_DEFAULT_ROLE"):
        default = role_service.get_by_name(current_app.config["LEMUR_DEFAULT_ROLE"])
        if not default:
            default = role_service.create(
                current_app.config["LEMUR_DEFAULT_ROLE"],
                description="This is the default Lemur role.",
            )
        roles.append(default)

    # Dedupe the roles
    roles = list(set(roles))

    return roles


def update_user(user, profile, roles):
    """Updates user with current profile information and associated roles.

    :param user:
    :param profile:
    :param roles:
    """
    # if we get an sso user create them an account
    if not user:
        user = user_service.create(
            profile["email"],
            get_psuedo_random_string(),
            profile["email"],
            True,
            profile.get("thumbnailPhotoUrl"),
            roles,
        )

    else:
        # we add 'lemur' specific roles, so they do not get marked as removed
        removed_roles = []
        for ur in user.roles:
            if not ur.third_party:
                roles.append(ur)
            elif ur not in roles:
                # This is a role assigned in lemur, but not returned by sso during current login
                removed_roles.append(ur.name)

        if removed_roles:
            log_service.audit_log("unassign_role", user.username, f"Un-assigning roles {removed_roles}")
        # update any changes to the user
        user_service.update(
            user.id,
            profile["email"],
            profile["email"],
            True,
            profile.get("thumbnailPhotoUrl"),  # profile isn't google+ enabled
            roles,
        )

    return user


def build_hmac():
    key = current_app.config.get('OAUTH_STATE_TOKEN_SECRET', None)
    if not key:
        current_app.logger.warning("OAuth State Token Secret not discovered in config. Generating one.")
        key = get_state_token_secret()
        current_app.config['OAUTH_STATE_TOKEN_SECRET'] = key  # store for remainder of Flask session

    try:
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    except TypeError:
        current_app.logger.error("OAuth State Token Secret must be bytes-like.")
        return None
    return h


def generate_state_token():
    t = int(time.time())
    ts = hex(t)[2:].encode('ascii')
    h = build_hmac()
    h.update(ts)
    digest = base64.b64encode(h.finalize())
    state = ts + b':' + digest
    return state.decode('utf-8')


def verify_state_token(token):
    stale_seconds = current_app.config.get('OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS', 15)
    try:
        state = token.encode('utf-8')
        ts, digest = state.split(b':')
        timestamp = int(ts, 16)
        if float(time.time() - timestamp) > stale_seconds:
            current_app.logger.warning('OAuth State token is too stale.')
            return False
        digest = base64.b64decode(digest)
    except ValueError as e:
        current_app.logger.warning(f'Error while parsing OAuth State token: {e}')
        return False

    try:
        h = build_hmac()
        h.update(ts)
        h.verify(digest)
        return True
    except InvalidSignature:
        current_app.logger.warning('OAuth State token is invalid.')
        return False
    except Exception as e:
        current_app.logger.warning(f'Error while parsing OAuth State token: {e}')
        return False


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
        super().__init__()

    @limiter.limit("10/5minute")
    def post(self):
        """
        .. http:post:: /auth/login

           Login with username:password

           **Example request**:

           .. sourcecode:: http

              POST /auth/login HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

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
        self.reqparse.add_argument("username", type=str, required=True, location="json")
        self.reqparse.add_argument("password", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        if "@" in args["username"]:
            user = user_service.get_by_email(args["username"])
        else:
            user = user_service.get_by_username(args["username"])

        # default to local authentication
        if user and user.check_password(args["password"]) and user.active:
            # Tell Flask-Principal the identity changed
            identity_changed.send(
                current_app._get_current_object(), identity=Identity(user.id)
            )

            metrics.send(
                "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
            )
            return dict(token=create_token(user))

        # try ldap login
        if current_app.config.get("LDAP_AUTH"):
            try:
                ldap_principal = ldap.LdapPrincipal(args)
                user = ldap_principal.authenticate()
                if user and user.active:
                    # Tell Flask-Principal the identity changed
                    identity_changed.send(
                        current_app._get_current_object(), identity=Identity(user.id)
                    )
                    metrics.send(
                        "login",
                        "counter",
                        1,
                        metric_tags={"status": SUCCESS_METRIC_STATUS},
                    )
                    return dict(token=create_token(user))
            except Exception as e:
                current_app.logger.error(f"ldap error: {e}")
                ldap_message = "ldap error: %s" % e
                metrics.send(
                    "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
                )
                return dict(message=ldap_message), 403

        # if not valid user - no certificates for you
        metrics.send(
            "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
        )
        return dict(message="The supplied credentials are invalid"), 403


class Ping(Resource):
    """
    This class serves as an example of how one might implement an SSO provider for use with Lemur. In
    this example we use an OpenIDConnect authentication flow, that is essentially OAuth2 underneath. If you have an
    OAuth2 provider you want to use Lemur there would be two steps:

    1. Define your own class that inherits from :class:`flask_restful.Resource` and create the HTTP methods the \
    provider uses for its callbacks.
    2. Add or change the Lemur AngularJS Configuration to point to your new provider
    """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def get(self):
        return "Redirecting..."

    def post(self):
        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get("PING_ACCESS_TOKEN_URL")

        secret = current_app.config.get("PING_SECRET")

        id_token, access_token = exchange_for_access_token(
            args["code"],
            args["redirectUri"],
            args["clientId"],
            secret,
            access_token_url=access_token_url,
        )

        jwks_url = current_app.config.get("PING_JWKS_URL")
        error_code = validate_id_token(id_token, args["clientId"], jwks_url)
        if error_code:
            return error_code

        user, profile = retrieve_user_memberships(
            current_app.config.get("PING_USER_API_URL"),
            current_app.config.get("USER_MEMBERSHIP_PROVIDER"),
            access_token
        )
        roles = create_user_roles(profile)
        user = update_user(user, profile, roles)

        if not user or not user.active:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid"), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.id)
        )

        metrics.send(
            "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )
        return dict(token=create_token(user))


class OAuth2(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def get(self):
        return "Redirecting..."

    def post(self):
        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")
        self.reqparse.add_argument("state", type=str, required=True, location="json")

        args = self.reqparse.parse_args()
        if not verify_state_token(args["state"]):
            return dict(message="The supplied credentials are invalid"), 403

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get("OAUTH2_ACCESS_TOKEN_URL")
        user_api_url = current_app.config.get("OAUTH2_USER_API_URL")
        verify_cert = current_app.config.get("OAUTH2_VERIFY_CERT")

        secret = current_app.config.get("OAUTH2_SECRET")

        id_token, access_token = exchange_for_access_token(
            args["code"],
            args["redirectUri"],
            args["clientId"],
            secret,
            access_token_url=access_token_url,
            verify_cert=verify_cert,
        )

        jwks_url = current_app.config.get("OAUTH2_JWKS_URL")
        error_code = validate_id_token(id_token, args["clientId"], jwks_url)
        if error_code:
            return error_code

        user, profile = retrieve_user(user_api_url, access_token)
        roles = create_user_roles(profile)
        user = update_user(user, profile, roles)

        if not user.active:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid"), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.id)
        )

        metrics.send(
            "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )

        return dict(token=create_token(user))


class Google(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super().__init__()

    def post(self):
        access_token_url = "https://accounts.google.com/o/oauth2/token"
        user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"

        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        # Step 1. Exchange authorization code for access token
        payload = {
            "client_id": args["clientId"],
            "grant_type": "authorization_code",
            "redirect_uri": args["redirectUri"],
            "code": args["code"],
            "client_secret": current_app.config.get("GOOGLE_SECRET"),
            "scope": "email",
        }

        r = requests.post(access_token_url, data=payload)
        token = r.json()

        # Step 2. Retrieve information about the current user
        headers = {"Authorization": "Bearer {}".format(token["access_token"])}

        r = requests.get(user_info_url, headers=headers)
        profile = r.json()

        user = user_service.get_by_email(profile["email"])

        if not (user and user.active):
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid."), 403

        if user:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
            )
            return dict(token=create_token(user))

        metrics.send(
            "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
        )


class Providers(Resource):
    def get(self):
        active_providers = []

        for provider in current_app.config.get("ACTIVE_PROVIDERS", []):
            provider = provider.lower()

            if provider == "google":
                active_providers.append(
                    {
                        "name": "google",
                        "clientId": current_app.config.get("GOOGLE_CLIENT_ID"),
                        "url": api.url_for(Google),
                    }
                )

            elif provider == "ping":
                active_providers.append(
                    {
                        "name": current_app.config.get("PING_NAME"),
                        "url": current_app.config.get("PING_URL", current_app.config.get("PING_REDIRECT_URI")),
                        "redirectUri": current_app.config.get("PING_REDIRECT_URI"),
                        "clientId": current_app.config.get("PING_CLIENT_ID"),
                        "responseType": "code",
                        "scope": ["openid", "email", "profile", "address"],
                        "scopeDelimiter": " ",
                        "authorizationEndpoint": current_app.config.get(
                            "PING_AUTH_ENDPOINT"
                        ),
                        "requiredUrlParams": ["scope"],
                        "type": "2.0",
                    }
                )

            elif provider == "oauth2":
                active_providers.append(
                    {
                        "name": current_app.config.get("OAUTH2_NAME"),
                        "url": current_app.config.get("OAUTH2_URL", current_app.config.get("OAUTH2_REDIRECT_URI")),
                        "redirectUri": current_app.config.get("OAUTH2_REDIRECT_URI"),
                        "clientId": current_app.config.get("OAUTH2_CLIENT_ID"),
                        "responseType": "code",
                        "scope": current_app.config.get("OAUTH2_SCOPE", ["openid", "email", "profile", "groups"]),
                        "scopeDelimiter": " ",
                        "authorizationEndpoint": current_app.config.get(
                            "OAUTH2_AUTH_ENDPOINT"
                        ),
                        "requiredUrlParams": ["scope", "state", "nonce"],
                        "state": generate_state_token(),
                        "nonce": get_psuedo_random_string(),
                        "type": "2.0",
                    }
                )

        return active_providers


api.add_resource(Login, "/auth/login", endpoint="login")
api.add_resource(Ping, "/auth/ping", endpoint="ping")
api.add_resource(Google, "/auth/google", endpoint="google")
api.add_resource(OAuth2, "/auth/oauth2", endpoint="oauth2")
api.add_resource(Providers, "/auth/providers", endpoint="providers")
