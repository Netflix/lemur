import json

import pytest

from lemur.roles.views import *  # noqa
from lemur.tests.factories import (
    RoleFactory,
    AuthorityFactory,
    CertificateFactory,
    UserFactory,
)
from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_role_input_schema(client):
    from lemur.roles.schemas import RoleInputSchema

    input_data = {"name": "myRole"}

    data, errors = RoleInputSchema().load(input_data)

    assert not errors


def test_multiple_authority_certificate_association(session, client):
    role = RoleFactory()
    authority = AuthorityFactory()
    certificate = CertificateFactory()
    authority1 = AuthorityFactory()
    certificate1 = CertificateFactory()

    role.authorities.append(authority)
    role.authorities.append(authority1)
    role.certificates.append(certificate)
    role.certificates.append(certificate1)

    session.commit()
    assert role.authorities[0].name == authority.name
    assert role.authorities[1].name == authority1.name
    assert role.certificates[0].name == certificate.name
    assert role.certificates[1].name == certificate1.name


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_role_get(client, token, status):
    assert (
        client.get(api.url_for(Roles, role_id=1), headers=token).status_code == status
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
def test_role_post_(client, token, status):
    assert (
        client.post(api.url_for(Roles, role_id=1), data={}, headers=token).status_code
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
def test_role_put(client, token, status):
    assert (
        client.put(api.url_for(Roles, role_id=1), data={}, headers=token).status_code
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
def test_role_put_with_data(client, session, token, status):
    user = UserFactory()
    role = RoleFactory()
    session.commit()

    data = {"users": [{"id": user.id}], "id": role.id, "name": role.name}

    assert (
        client.put(
            api.url_for(Roles, role_id=role.id), data=json.dumps(data), headers=token
        ).status_code
        == status
    )


def test_role_put_with_data_and_user(client, session):
    from lemur.auth.service import create_token

    user = UserFactory()
    role = RoleFactory(users=[user])
    role1 = RoleFactory()
    user1 = UserFactory()
    session.commit()

    headers = {
        "Authorization": "Basic " + create_token(user),
        "Content-Type": "application/json",
    }

    data = {
        "users": [{"id": user1.id}, {"id": user.id}],
        "id": role.id,
        "name": role.name,
    }

    assert (
        client.put(
            api.url_for(Roles, role_id=role.id), data=json.dumps(data), headers=headers
        ).status_code
        == 200
    )
    assert (
        client.get(api.url_for(RolesList), data={}, headers=headers).json["total"] > 1
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
def test_role_delete(client, token, status, role):
    assert (
        client.delete(api.url_for(Roles, role_id=role.id), headers=token).status_code
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
def test_role_patch(client, token, status):
    assert (
        client.patch(api.url_for(Roles, role_id=1), data={}, headers=token).status_code
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
def test_role_list_post_(client, token, status):
    assert (
        client.post(api.url_for(RolesList), data={}, headers=token).status_code
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
def test_role_list_get(client, token, status):
    assert client.get(api.url_for(RolesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_role_list_delete(client, token, status):
    assert client.delete(api.url_for(RolesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_role_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(RolesList), data={}, headers=token).status_code
        == status
    )


def test_sensitive_filter(client):
    resp = client.get(
        api.url_for(RolesList) + "?filter=password;a", headers=VALID_ADMIN_HEADER_TOKEN
    )
    assert "'password' is not sortable or filterable" in resp.json["message"]
