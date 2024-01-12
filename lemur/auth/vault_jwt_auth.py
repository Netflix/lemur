from __future__ import absolute_import
import random
import jwt
import jwt.algorithms
import requests
import simplejson as json

from cachetools import TTLCache
from jwt.algorithms import get_default_algorithms
from jwt.exceptions import InvalidKeyError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_DEFAULT_TIMEOUT = (0.1, 0.5)  # connect_timeout=100ms read_timeout=500ms
_DEFAULT_RETRY_POLICY = Retry(
    total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
)


def format_url_for_issuer_internal_keys(issuer):
    return "{}/.well-known/keys".format(issuer.rstrip("/"))


def format_url_for_issuer_token(issuer, name):
    return "{}/token/{}".format(issuer.rstrip("/"), name)


def parse_cache_control_header(headers):
    header = (headers or {}).get("Cache-Control", "")
    try:
        for d in header.split(","):
            d = d.lower().strip()
            if d.startswith("max-age="):
                return int(d[8:])
    except Exception:
        return 0

    return 0


class PyJWK(object):
    def __init__(self, jwk_data, algorithm=None):
        self._algorithms = get_default_algorithms()
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError("kty is not found: %s" % self._jwk_data)

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            raise Exception(
                "Unable to find a algorithm for key %s" % self._jwk_data.keys()
            )

        self.algorithm_name = algorithm
        self.Algorithm = self._algorithms.get(self.algorithm_name)

        if not self.Algorithm:
            raise Exception("Unable to find a algorithm for key: %s" % self._jwk_data)

        self.key = self.Algorithm.from_jwk(json.dumps(self._jwk_data))

    @staticmethod
    def from_dict(obj, algorithm=None):
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data, algorithm=None):
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self):
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self):
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self):
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(self, keys):
        self.keys_by_id = {}

        if not keys or not isinstance(keys, list):
            raise Exception("Invalid JWK Set value")

        if len(keys) == 0:
            raise Exception("The JWK Set did not contain any keys")

        for key in keys:
            k = PyJWK(key)
            self.keys_by_id[k.key_id] = k

    @staticmethod
    def from_dict(obj):
        keys = obj.get("keys", [])
        return PyJWKSet(keys)


class TimeoutRetryingHTTPAdapter(HTTPAdapter):
    def __init__(self, timeout=None, retry_policy=None, *args, **kwargs):
        timeout_value = timeout
        if timeout_value is None:
            timeout_value = _DEFAULT_TIMEOUT
        elif not isinstance(timeout_value, tuple):
            # a request_timeout only, use sane default connect_timeout
            timeout_value = (_DEFAULT_TIMEOUT[0], timeout_value)
        self.timeout = timeout_value

        self.max_retries = _DEFAULT_RETRY_POLICY
        if isinstance(retry_policy, Retry):
            self.max_retries = retry_policy
        super(TimeoutRetryingHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        elif not isinstance(timeout, tuple):
            # a request_timeout only, use sane default connect_timeout
            kwargs["timeout"] = (_DEFAULT_TIMEOUT[0], timeout)
        return super(TimeoutRetryingHTTPAdapter, self).send(request, **kwargs)


class JWTAuthenticator(object):
    _TTL_MARGIN = 300  # 5 minutes in seconds

    _instances = {}

    @classmethod
    def instance(
        cls,
        name,
        audience,
        issuers,
        timeout=None,
    ):
        if name not in cls._instances:
            cls._instances[name] = JWTAuthenticator(
                audience=audience,
                issuers=issuers,
                timeout=timeout,
            )
        return cls._instances[name]

    def __init__(
        self,
        audience,
        issuers,
        timeout=None,
    ):
        assert audience  # ensure an audience is set always
        self.audience = audience
        self.issuers = issuers
        self.keys = {issuer: None for issuer in self.issuers}
        self._session = requests.Session()
        self._session_adapter = TimeoutRetryingHTTPAdapter(timeout=timeout)
        self._session.mount("http://", self._session_adapter)
        self._session.mount("https://", self._session_adapter)

    def _make_issuer_request(self, issuer):
        headers = {
            "X-Vault-Request": "true",  # be compatible with Vault
        }
        response = self._session.get(
            format_url_for_issuer_internal_keys(issuer), headers=headers
        )
        cache_control = parse_cache_control_header(response.headers)
        return response.json(), cache_control

    def _get_keys_internal(self, issuer):
        keys_json, cache_control = self._make_issuer_request(issuer)
        cache_control_jitter = max(cache_control - random.randint(15, 30), 1)
        key_set = PyJWKSet.from_dict(keys_json)
        self.keys[issuer] = TTLCache(1000, cache_control_jitter)
        for key_id, key in key_set.keys_by_id.items():
            self.keys[issuer][key_id] = key

    def _get_public_keys(self, issuer, key_id):
        # First check that the issuer is allowed (must be in self.keys)
        if issuer not in self.issuers:
            raise Exception(f"Issuer '{issuer}' is invalid'")

        # Check that there is something at self.keys[issuer]
        # This should only be the case at start-up.
        if self.keys[issuer] is None:
            self._get_keys_internal(issuer)
            return self.keys[issuer][key_id]

        # Normal flow
        # - try to find cached key
        # - fetch the keys if it's not there.
        try:
            return self.keys[issuer][key_id]
        except KeyError:
            self._get_keys_internal(issuer)
            return self.keys[issuer][key_id]

    def authenticate(self, token):
        unverified_header = jwt.get_unverified_header(token)
        unverified_body = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False}
        )
        unverified_key_id = unverified_header.get("kid")
        unverified_issuer = unverified_body.get("iss")

        relevant_key = None
        jwk_set_key = self._get_public_keys(unverified_issuer, unverified_key_id)
        if (
            jwk_set_key.public_key_use == "sig"
            and jwk_set_key.key_id
            and jwk_set_key.key_id == unverified_key_id
        ):
            relevant_key = jwk_set_key

        if relevant_key is None:
            raise Exception(
                f"Could not find key '{unverified_key_id}' issuer '{unverified_issuer}'"
            )

        options = {
            "verify_signature": True,  # always validate the signature
            "verify_iss": True,  # verify the issuer is what we expected
            "verify_aud": True,  # verify our audience is valid and us
            "verify_exp": True,  # verify expiration time is valid within leeway
            "verify_iat": True,  # verify issued at is valid within leeway
            "verify_nbf": True,  # verify not before is valid within leeway
        }
        data = jwt.decode(
            token,
            relevant_key.key,
            audience=self.audience,
            algorithms=[relevant_key.algorithm_name],
            options=options,
        )

        return data
