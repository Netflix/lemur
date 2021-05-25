from datetime import datetime, timedelta
from freezegun import freeze_time

from flask import current_app

from lemur.auth.views import *  # noqa
from lemur.tests.conf import OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS, OAUTH_STATE_TOKEN_SECRET


def test_build_hmac(client):
    from lemur.auth.views import build_hmac

    assert isinstance(build_hmac(), hmac.HMAC)

    # make a bad key
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = 'not-bytes-like'
    assert not build_hmac()

    # put back a good key, for remaining tests
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = OAUTH_STATE_TOKEN_SECRET


def test_generate_state_token(client):
    from lemur.auth.views import generate_state_token

    assert generate_state_token()


def test_verify_state_token(client):
    from lemur.auth.views import generate_state_token
    from lemur.auth.views import verify_state_token

    token = generate_state_token()
    assert verify_state_token(token)

    with freeze_time(datetime.now() - timedelta(seconds=OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS), tick=True):
        stale_token = generate_state_token()
    assert not verify_state_token(stale_token)

    assert not verify_state_token('123456:f4k8')
    assert not verify_state_token('123456::f4k8')
    assert not verify_state_token('123456f4k8')
    assert not verify_state_token('')

    # force a new key to get generated and stored at runtime
    current_app.config["OAUTH_STATE_TOKEN_SECRET"] = None
    token_via_runtime_key = generate_state_token()
    assert verify_state_token(token_via_runtime_key)
