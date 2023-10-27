from unittest.mock import patch

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
