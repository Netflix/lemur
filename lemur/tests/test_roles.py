import pytest

from lemur.roles.views import *  # noqa


from .vectors import VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN


def test_role_input_schema(client):
    from lemur.roles.schemas import RoleInputSchema

    input_data = {
        'name': 'myRole'
    }

    data, errors = RoleInputSchema().load(input_data)

    assert not errors


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_role_get(client, token, status):
    assert client.get(api.url_for(Roles, role_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_role_post_(client, token, status):
    assert client.post(api.url_for(Roles, role_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_role_put(client, token, status):
    assert client.put(api.url_for(Roles, role_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_role_delete(client, token, status):
    assert client.delete(api.url_for(Roles, role_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_role_patch(client, token, status):
    assert client.patch(api.url_for(Roles, role_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_role_list_post_(client, token, status):
    assert client.post(api.url_for(RolesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_role_list_get(client, token, status):
    assert client.get(api.url_for(RolesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_role_list_delete(client, token, status):
    assert client.delete(api.url_for(RolesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_role_list_patch(client, token, status):
    assert client.patch(api.url_for(RolesList), data={}, headers=token).status_code == status
