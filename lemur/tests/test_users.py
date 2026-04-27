import json

import pytest
from marshmallow import ValidationError

from lemur.tests.factories import UserFactory, RoleFactory
from lemur.users.schemas import UserInputSchema, UserCreateInputSchema
from lemur.users.views import *  # noqa
from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_user_input_schema(client):
    input_data = {
        "username": "example",
        "password": "1233432",
        "email": "example@example.com",
    }

    data, errors = UserInputSchema().load(input_data)

    assert not errors


def test_valid_password():
    schema = UserCreateInputSchema()
    good_password = "ABcdefg123456@#]"
    # This password should not raise an exception
    schema.validate_password(good_password)


@pytest.mark.parametrize(
    "bad_password",
    [
        "ABCD1234!#]",  # No lowercase
        "abcd1234@#]",  # No uppercase
        "!@#]Abcdefg",  # No digit
        "ABCDabcd1234",  # No special character
        "Ab1!@#]",  # less than 12 characters
    ],
)
def test_invalid_password(bad_password):
    schema = UserCreateInputSchema()
    # All these passwords should raise an exception
    with pytest.raises(ValidationError):
        schema.validate_password(bad_password)


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_user_get(client, token, status):
    assert (
        client.get(api.url_for(Users, user_id=1), headers=token).status_code == status
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
def test_user_post_(client, token, status):
    assert (
        client.post(api.url_for(Users, user_id=1), data={}, headers=token).status_code
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
def test_user_put(client, token, status):
    assert (
        client.put(api.url_for(Users, user_id=1), data={}, headers=token).status_code
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
def test_user_delete(client, token, status):
    assert (
        client.delete(api.url_for(Users, user_id=1), headers=token).status_code
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
def test_user_patch(client, token, status):
    assert (
        client.patch(api.url_for(Users, user_id=1), data={}, headers=token).status_code
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
def test_user_list_post_(client, token, status):
    assert (
        client.post(api.url_for(UsersList), data={}, headers=token).status_code
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
def test_user_list_get(client, token, status):
    assert client.get(api.url_for(UsersList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_list_delete(client, token, status):
    assert client.delete(api.url_for(UsersList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_user_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(UsersList), data={}, headers=token).status_code
        == status
    )


def test_sensitive_filter(client):
    resp = client.get(
        api.url_for(UsersList) + "?filter=password;a", headers=VALID_ADMIN_HEADER_TOKEN
    )
    assert "'password' is not sortable or filterable" in resp.json["message"]


def test_sensitive_sort(client):
    resp = client.get(
        api.url_for(UsersList) + "?sortBy=password&sortDir=asc",
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert "'password' is not sortable or filterable" in resp.json["message"]


def test_user_role_changes(client, session):
    user = UserFactory()
    role1 = RoleFactory()
    role2 = RoleFactory()
    session.flush()

    data = {
        "active": True,
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [{"id": role1.id}, {"id": role2.id}],
    }

    # PUT two roles
    resp = client.put(
        api.url_for(Users, user_id=user.id),
        data=json.dumps(data),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    assert len(resp.json["roles"]) == 2
    assert set(user.roles) == {role1, role2}

    # Remove one role and PUT again
    del data["roles"][1]
    resp = client.put(
        api.url_for(Users, user_id=user.id),
        data=json.dumps(data),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    assert len(resp.json["roles"]) == 1
    assert set(user.roles) == {role1}
