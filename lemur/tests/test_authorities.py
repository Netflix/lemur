import json

import pytest

from lemur.authorities.views import *  # noqa
from lemur.tests.factories import AuthorityFactory, RoleFactory
from lemur.tests.vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_authority_input_schema(client, role, issuer_plugin, logged_in_user):
    from lemur.authorities.schemas import AuthorityInputSchema

    input_data = {
        "name": "Example Authority",
        "owner": "jim@example.com",
        "description": "An example authority.",
        "commonName": "An Example Authority",
        "plugin": {
            "slug": "test-issuer",
            "plugin_options": [{"name": "test", "value": "blah"}],
        },
        "type": "root",
        "signingAlgorithm": "sha256WithRSA",
        "keyType": "RSA2048",
        "sensitivity": "medium",
    }

    data, errors = AuthorityInputSchema().load(input_data)

    assert not errors


def test_authority_input_schema_ecc(client, role, issuer_plugin, logged_in_user):
    from lemur.authorities.schemas import AuthorityInputSchema

    input_data = {
        "name": "Example Authority",
        "owner": "jim@example.com",
        "description": "An example authority.",
        "commonName": "An Example Authority",
        "plugin": {
            "slug": "test-issuer",
            "plugin_options": [{"name": "test", "value": "blah"}],
        },
        "type": "root",
        "signingAlgorithm": "sha256WithECDSA",
        "keyType": "ECCPRIME256V1",
        "sensitivity": "medium",
    }

    data, errors = AuthorityInputSchema().load(input_data)

    assert not errors


def test_user_authority(session, client, authority, role, user, issuer_plugin):
    u = user["user"]
    u.roles.append(role)
    authority.roles.append(role)
    session.commit()
    assert (
        client.get(api.url_for(AuthoritiesList), headers=user["token"]).json["total"]
        == 1
    )
    u.roles.remove(role)
    session.commit()
    assert (
        client.get(api.url_for(AuthoritiesList), headers=user["token"]).json["total"]
        == 0
    )


def test_create_authority(issuer_plugin, user):
    from lemur.authorities.service import create
    from lemur.tests.factories import RoleFactory

    authority = create(
        plugin={"plugin_object": issuer_plugin, "slug": issuer_plugin.slug},
        owner=user["user"].email,
        type="root",
        name="example authority",
        creator=user["user"],
        roles=[RoleFactory(name="new-role-test_create_authority")]
    )
    assert authority.authority_certificate
    assert authority.owner == user["user"].email
    assert len(authority.roles) == 3
    for role in authority.roles:
        assert role.name in [user["user"].email, "test_example_authority_admin", "new-role-test_create_authority"]
    assert "test_example_authority_admin" not in user["user"].roles
    assert "new-role-test_create_authority" not in user["user"].roles


@pytest.mark.parametrize(
    "token, count",
    [
        (VALID_USER_HEADER_TOKEN, 0),
        (VALID_ADMIN_HEADER_TOKEN, 3),
        (VALID_ADMIN_API_TOKEN, 3),
    ],
)
def test_admin_authority(client, authority, issuer_plugin, token, count):
    assert (
        client.get(api.url_for(AuthoritiesList), headers=token).json["total"] == count
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
def test_authority_get(client, token, status):
    assert (
        client.get(api.url_for(Authorities, authority_id=1), headers=token).status_code
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
def test_authority_post(client, token, status):
    assert (
        client.post(
            api.url_for(Authorities, authority_id=1), data={}, headers=token
        ).status_code
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
def test_authority_put(client, token, status):
    assert (
        client.put(
            api.url_for(Authorities, authority_id=1), data={}, headers=token
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
def test_authority_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(Authorities, authority_id=1), headers=token
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
def test_authority_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Authorities, authority_id=1), data={}, headers=token
        ).status_code
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
def test_authorities_get(client, token, status):
    assert client.get(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_authorities_post(client, token, status):
    assert (
        client.post(api.url_for(AuthoritiesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,authority_number,status",
    [
        (VALID_USER_HEADER_TOKEN, 1, 403),
        (VALID_ADMIN_HEADER_TOKEN, 2, 200),
        (VALID_ADMIN_API_TOKEN, 3, 200),
        ("", 4, 401),
    ],
)
def test_authorities_post_with_data(client, authority_number, token, status):
    """
    This test relies on the configuration option ADMIN_ONLY_AUTHORITY_CREATION = True, set in conf.py
    """
    response = client.post(
        api.url_for(AuthoritiesList),
        data=json.dumps({'name': f'testauthority{authority_number}', 'owner': 'test@example.com',
                         'common_name': 'testauthority1.example.com', "serial_number": 1,
                         "validityStart": "2023-07-12T07:00:00.000Z",
                         "validityEnd": "2050-07-13T07:00:00.000Z",
                         'plugin': {'slug': 'cryptography-issuer'}}),
        headers=token
    )
    assert response.status_code == status, f"expected code {status}, but actual code was {response.status_code}; error: {response.json}"


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_authorities_put(client, token, status):
    assert (
        client.put(api.url_for(AuthoritiesList), data={}, headers=token).status_code
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
def test_authorities_delete(client, token, status):
    assert (
        client.delete(api.url_for(AuthoritiesList), headers=token).status_code == status
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
def test_authorities_patch(client, token, status):
    assert (
        client.patch(api.url_for(AuthoritiesList), data={}, headers=token).status_code
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
def test_certificate_authorities_get(client, token, status):
    assert client.get(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_certificate_authorities_post(client, token, status):
    assert (
        client.post(api.url_for(AuthoritiesList), data={}, headers=token).status_code
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
def test_certificate_authorities_put(client, token, status):
    assert (
        client.put(api.url_for(AuthoritiesList), data={}, headers=token).status_code
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
def test_certificate_authorities_delete(client, token, status):
    assert (
        client.delete(api.url_for(AuthoritiesList), headers=token).status_code == status
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
def test_certificate_authorities_patch(client, token, status):
    assert (
        client.patch(api.url_for(AuthoritiesList), data={}, headers=token).status_code
        == status
    )


def test_authority_roles(client, session, issuer_plugin):
    auth = AuthorityFactory()
    role = RoleFactory()
    session.flush()

    data = {
        "owner": auth.owner,
        "name": auth.name,
        "description": auth.description,
        "active": True,
        "roles": [{"id": role.id}],
    }

    # Add role
    resp = client.put(
        api.url_for(Authorities, authority_id=auth.id),
        data=json.dumps(data),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    assert len(resp.json["roles"]) == 1
    assert set(auth.roles) == {role}

    # Remove role
    del data["roles"][0]
    resp = client.put(
        api.url_for(Authorities, authority_id=auth.id),
        data=json.dumps(data),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    assert len(resp.json["roles"]) == 0


@pytest.mark.parametrize(
    "token,authority_number,status",
    [
        (VALID_ADMIN_HEADER_TOKEN, 100, 200),
    ],
)
def test_authorities_put_update_options(client, authority_number, token, status):
    """
    This test relies on the configuration option ADMIN_ONLY_AUTHORITY_CREATION = True, set in conf.py
    """
    data = {'name': f'testauthority{authority_number}', 'owner': 'test@example.com',
            'common_name': 'testauthority1.example.com', "serial_number": 1,
            "validityStart": "2023-07-12T07:00:00.000Z",
            "validityEnd": "2050-07-13T07:00:00.000Z",
            'plugin': {'slug': 'cryptography-issuer'}}
    response = client.post(
        api.url_for(AuthoritiesList),
        data=json.dumps(data),
        headers=token
    )
    assert response.status_code == status, f"expected code {status}, but actual code was {response.status_code}; error: {response.json}"
    response = json.loads(
        client.put(
            api.url_for(Authorities, authority_id=1), data=json.dumps(
                {'owner': 'updated@example.com',
                 'description': 'updated',
                 'roles': [],
                 'options': json.dumps([{'updated': 'bar'}])}), headers=token
        ).text
    )
    for field in ['owner', 'description', 'options']:
        assert 'updated' in json.dumps(response[field])
