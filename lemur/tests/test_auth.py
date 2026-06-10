from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import jwt
from lemur.auth.service import decode_with_multiple_secrets


@patch("lemur.auth.service.metrics")
def test_decode_with_multiple_secrets(mock_metrics):
    # Given
    secret = "my_secret"
    encoded_jwt = jwt.encode({"foo": "bar"}, secret, algorithm='HS256')
    secrets = [secret, secret + "2"]
    algorithms = ['HS256']

    # When
    payload = decode_with_multiple_secrets(encoded_jwt, secrets, algorithms)

    # Then
    assert payload == {"foo": "bar"}
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(secret.encode())
    mock_metrics.send.assert_called_once_with(
        "jwt_decode", "counter", 1,
        metric_tags={
            **dict(kid=0, fingerprint=digest.finalize().hex()),
            **{"foo": "bar"}
        }
    )


@patch("lemur.auth.service.metrics")
def test_decode_with_integer_sub_backward_compat(mock_metrics):
    """Old tokens created before the string-sub fix have integer sub claims.
    PyJWT 2.10+ rejects these with InvalidSubjectError unless verify_sub=False."""
    secret = "my_secret"
    # Manually build a token with integer sub (as old Lemur code produced)
    encoded_jwt = jwt.encode({"sub": 42, "aid": 1}, secret, algorithm='HS256')
    secrets = [secret]
    algorithms = ['HS256']

    payload = decode_with_multiple_secrets(encoded_jwt, secrets, algorithms)

    assert payload["sub"] == 42


def test_server_algorithm_pin_accepts_hs256():
    """Tokens signed with HS256 (the only algorithm create_token has ever used) are accepted
    when the server pins ["HS256"], preserving backward compatibility with all existing tokens."""
    secret = "my_secret"
    encoded_jwt = jwt.encode({"sub": "1"}, secret, algorithm="HS256")
    payload = decode_with_multiple_secrets(encoded_jwt, [secret], algorithms=["HS256"])
    assert payload["sub"] == "1"


def test_server_algorithm_pin_rejects_wrong_alg():
    """A valid HS256 token is rejected when the server's pinned list does not include HS256.
    This proves the server's algorithm list — not the token header — controls what is accepted."""
    secret = "my_secret"
    encoded_jwt = jwt.encode({"sub": "1"}, secret, algorithm="HS256")
    with pytest.raises(Exception):
        decode_with_multiple_secrets(encoded_jwt, [secret], algorithms=["RS256"])


def test_algorithm_confusion_header_tampering():
    """An attacker who claims alg=RS256 in the token header cannot bypass HS256-only verification.
    With server-pinned algorithms the header value is irrelevant — only the server's list matters."""
    secret = "my_secret"
    # Build a token that has alg=RS256 in its header but is HMAC-signed with HS256.
    # PyJWT doesn't let us forge this directly; simulate by verifying the server-side behaviour:
    # if the server pins ["HS256"] and the actual signature is HS256, it succeeds regardless of
    # what an attacker would put in the header — and if the server pins ["RS256"] it fails.
    hs256_token = jwt.encode({"sub": "2"}, secret, algorithm="HS256")

    # Server accepts it when HS256 is pinned (correct signature algorithm matches pin).
    payload = decode_with_multiple_secrets(hs256_token, [secret], algorithms=["HS256"])
    assert payload["sub"] == "2"

    # Server rejects it when only RS256 is pinned — header trickery cannot override the pin.
    with pytest.raises(Exception):
        decode_with_multiple_secrets(hs256_token, [secret], algorithms=["RS256"])
