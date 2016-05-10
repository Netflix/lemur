import pytest

from lemur.users.views import *  # noqa


from .vectors import VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN


def test_user_input_schema(client):
    from lemur.users.schemas import UserInputSchema

    input_data = {
        'username': 'example',
        'password': '1233432',
        'email': 'example@example.com'
    }

    data, errors = UserInputSchema().load(input_data)

    assert not errors


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_user_get(client, token, status):
    assert client.get(api.url_for(Users, user_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_user_post_(client, token, status):
    assert client.post(api.url_for(Users, user_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_user_put(client, token, status):
    assert client.put(api.url_for(Users, user_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_user_delete(client, token, status):
    assert client.delete(api.url_for(Users, user_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_user_patch(client, token, status):
    assert client.patch(api.url_for(Users, user_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_user_list_post_(client, token, status):
    assert client.post(api.url_for(UsersList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 404),
    (VALID_ADMIN_HEADER_TOKEN, 404),
    ('', 401)
])
def test_user_list_get(client, token, status):
    assert client.get(api.url_for(UsersList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_user_list_delete(client, token, status):
    assert client.delete(api.url_for(UsersList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_user_list_patch(client, token, status):
    assert client.patch(api.url_for(UsersList), data={}, headers=token).status_code == status
