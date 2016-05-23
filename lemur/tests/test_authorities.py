
import pytest
from lemur.authorities.views import *  # noqa

from .vectors import VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN


def test_authority_input_schema(client, role):
    from lemur.authorities.schemas import AuthorityInputSchema

    input_data = {
        'name': 'Example Authority',
        'owner': 'jim@example.com',
        'description': 'An example authority.',
        'commonName': 'AnExampleAuthority',
        'pluginName': {'slug': 'verisign-issuer'},
        'type': 'root',
        'signingAlgorithm': 'sha256WithRSA',
        'keyType': 'RSA2048',
        'sensitivity': 'medium'
    }

    data, errors = AuthorityInputSchema().load(input_data)

    assert not errors


def test_user_authority(session, client, authority, role, user):
    assert client.get(api.url_for(AuthoritiesList), headers=user['token']).json['total'] == 0
    u = user['user']
    u.roles.append(role)
    authority.roles.append(role)
    session.commit()
    assert client.get(api.url_for(AuthoritiesList), headers=user['token']).json['total'] == 1
    u.roles.remove(role)
    session.commit()
    assert client.get(api.url_for(AuthoritiesList), headers=user['token']).json['total'] == 0


def test_create_authority(issuer_plugin, logged_in_admin):
    from lemur.authorities.service import create
    authority = create(plugin={'plugin_object': issuer_plugin, 'slug': issuer_plugin.slug}, owner='jim@example.com', type='root')
    assert authority.authority_certificate


@pytest.mark.parametrize("token, count", [
    (VALID_USER_HEADER_TOKEN, 0),
    (VALID_ADMIN_HEADER_TOKEN, 3)
])
def test_admin_authority(client, authority, token, count):
    assert client.get(api.url_for(AuthoritiesList), headers=token).json['total'] == count


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_authority_get(client, token, status):
    assert client.get(api.url_for(Authorities, authority_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authority_post(client, token, status):
    assert client.post(api.url_for(Authorities, authority_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_authority_put(client, token, status):
    assert client.put(api.url_for(Authorities, authority_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authority_delete(client, token, status):
    assert client.delete(api.url_for(Authorities, authority_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authority_patch(client, token, status):
    assert client.patch(api.url_for(Authorities, authority_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_authorities_get(client, token, status):
    assert client.get(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_authorities_post(client, token, status):
    assert client.post(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authorities_put(client, token, status):
    assert client.put(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authorities_delete(client, token, status):
    assert client.delete(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_authorities_patch(client, token, status):
    assert client.patch(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_certificate_authorities_get(client, token, status):
    assert client.get(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_certificate_authorities_post(client, token, status):
    assert client.post(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_authorities_put(client, token, status):
    assert client.put(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_authorities_delete(client, token, status):
    assert client.delete(api.url_for(AuthoritiesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_authorities_patch(client, token, status):
    assert client.patch(api.url_for(AuthoritiesList), data={}, headers=token).status_code == status
