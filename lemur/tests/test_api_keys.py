import json
import pytest

from lemur.api_keys.views import *  # noqa


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_api_key_list_get(client, token, status):
    assert client.get(api.url_for(ApiKeyList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_api_key_list_post_invalid(client, token, status):
    assert (
        client.post(api.url_for(ApiKeyList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,user_id,status",
    [
        (VALID_USER_HEADER_TOKEN, 1, 200),
        (VALID_ADMIN_HEADER_TOKEN, 2, 200),
        (VALID_ADMIN_API_TOKEN, 2, 200),
        ("", 0, 401),
    ],
)
def test_api_key_list_post_valid_self(client, user_id, token, status):
    assert (
        client.post(
            api.url_for(ApiKeyList),
            data=json.dumps(
                {
                    "name": "a test token",
                    "user": {
                        "id": user_id,
                        "username": "example",
                        "email": "example@test.net",
                    },
                    "ttl": -1,
                }
            ),
            headers=token,
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_api_key_list_post_valid_no_permission(client, token, status):
    assert (
        client.post(
            api.url_for(ApiKeyList),
            data=json.dumps(
                {
                    "name": "a test token",
                    "user": {
                        "id": 2,
                        "username": "example",
                        "email": "example@test.net",
                    },
                    "ttl": -1,
                }
            ),
            headers=token,
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_api_key_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(ApiKeyList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_api_key_list_delete(client, token, status):
    assert client.delete(api.url_for(ApiKeyList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_user_api_key_list_get(client, token, status):
    assert (
        client.get(api.url_for(ApiKeyUserList, user_id=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_user_api_key_list_post_invalid(client, token, status):
    assert (
        client.post(
            api.url_for(ApiKeyUserList, user_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,user_id,status",
    [
        (VALID_USER_HEADER_TOKEN, 1, 200),
        (VALID_ADMIN_HEADER_TOKEN, 2, 200),
        (VALID_ADMIN_API_TOKEN, 2, 200),
        ("", 0, 401),
    ],
)
def test_user_api_key_list_post_valid_self(client, user_id, token, status):
    assert (
        client.post(
            api.url_for(ApiKeyUserList, user_id=1),
            data=json.dumps(
                {"name": "a test token", "user": {"id": user_id}, "ttl": -1}
            ),
            headers=token,
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_user_api_key_list_post_valid_no_permission(client, token, status):
    assert (
        client.post(
            api.url_for(ApiKeyUserList, user_id=2),
            data=json.dumps({"name": "a test token", "user": {"id": 2}, "ttl": -1}),
            headers=token,
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_api_key_list_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(ApiKeyUserList, user_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_api_key_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(ApiKeyUserList, user_id=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
@pytest.mark.skip(
    reason="no way of getting an actual user onto the access key to generate a jwt"
)
def test_api_key_get(client, token, status):
    assert client.get(api.url_for(ApiKeys, aid=1), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_api_key_post(client, token, status):
    assert client.post(api.url_for(ApiKeys, aid=1), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_api_key_patch(client, token, status):
    assert (
        client.patch(api.url_for(ApiKeys, aid=1), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
@pytest.mark.skip(
    reason="no way of getting an actual user onto the access key to generate a jwt"
)
def test_api_key_put_permssions(client, token, status):
    assert (
        client.put(
            api.url_for(ApiKeys, aid=1),
            data=json.dumps({"name": "Test", "revoked": False, "ttl": -1}),
            headers=token,
        ).status_code
        == status
    )


# This test works while the other doesn't because the schema allows user id to be null.
@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_api_key_described_get(client, token, status):
    assert (
        client.get(api.url_for(ApiKeysDescribed, aid=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
@pytest.mark.skip(
    reason="no way of getting an actual user onto the access key to generate a jwt"
)
def test_user_api_key_get(client, token, status):
    assert (
        client.get(api.url_for(UserApiKeys, uid=1, aid=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_api_key_post(client, token, status):
    assert (
        client.post(
            api.url_for(UserApiKeys, uid=2, aid=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_api_key_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(UserApiKeys, uid=2, aid=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
@pytest.mark.skip(
    reason="no way of getting an actual user onto the access key to generate a jwt"
)
def test_user_api_key_put_permssions(client, token, status):
    assert (
        client.put(
            api.url_for(UserApiKeys, uid=2, aid=1),
            data=json.dumps({"name": "Test", "revoked": False, "ttl": -1}),
            headers=token,
        ).status_code
        == status
    )
