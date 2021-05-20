from lemur.auth.views import *  # noqa


def test_build_hmac(client):
    from lemur.auth.views import build_hmac

    assert isinstance(build_hmac(), hmac.HMAC)


def test_generate_state_token(client):
    from lemur.auth.views import generate_state_token

    assert generate_state_token()


def test_verify_state_token(client):
    from lemur.auth.views import generate_state_token
    from lemur.auth.views import verify_state_token

    token = generate_state_token()
    assert verify_state_token(token)
    assert not verify_state_token('123456:f4k8')
