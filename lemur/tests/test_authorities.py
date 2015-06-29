import pytest
from lemur.authorities.views import *

#def test_crud(session):
#    role = create('role1')
#    assert role.id > 0
#
#    role = update(role.id, 'role_new', None, [])
#    assert role.name == 'role_new'
#    delete(role.id)
#    assert get(role.id) == None


def test_authority_get(client):
    assert client.get(api.url_for(Authorities, authority_id=1)).status_code == 401


def test_authority_post(client):
    assert client.post(api.url_for(Authorities, authority_id=1), {}).status_code == 405


def test_authority_put(client):
    assert client.put(api.url_for(Authorities, authority_id=1), {}).status_code == 401


def test_authority_delete(client):
    assert client.delete(api.url_for(Authorities, authority_id=1)).status_code == 405


def test_authority_patch(client):
    assert client.patch(api.url_for(Authorities, authority_id=1), {}).status_code == 405


def test_authorities_get(client):
    assert client.get(api.url_for(AuthoritiesList)).status_code == 401


def test_authorities_post(client):
    assert client.post(api.url_for(AuthoritiesList), {}).status_code == 401


def test_authorities_put(client):
    assert client.put(api.url_for(AuthoritiesList), {}).status_code == 405


def test_authorities_delete(client):
    assert client.delete(api.url_for(AuthoritiesList)).status_code == 405


def test_authorities_patch(client):
    assert client.patch(api.url_for(AuthoritiesList), {}).status_code == 405


def test_certificate_authorities_get(client):
    assert client.get(api.url_for(AuthoritiesList)).status_code == 401


def test_certificate_authorities_post(client):
    assert client.post(api.url_for(AuthoritiesList), {}).status_code == 401


def test_certificate_authorities_put(client):
    assert client.put(api.url_for(AuthoritiesList), {}).status_code == 405


def test_certificate_authorities_delete(client):
    assert client.delete(api.url_for(AuthoritiesList)).status_code == 405


def test_certificate_authorities_patch(client):
    assert client.patch(api.url_for(AuthoritiesList), {}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_authority_get(client):
    assert client.get(api.url_for(Authorities, authority_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_authority_post_(client):
    assert client.post(api.url_for(Authorities, authority_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_put(client):
    assert client.put(api.url_for(Authorities, authority_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_authority_delete(client):
    assert client.delete(api.url_for(Authorities, authority_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_patch(client):
    assert client.patch(api.url_for(Authorities, authority_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authorities_get(client):
    assert client.get(api.url_for(AuthoritiesList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_authorities_post(client):
    assert client.post(api.url_for(AuthoritiesList), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_certificates_authorities_get(client):
    assert client.get(api.url_for(CertificateAuthority, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 404


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_authority_get(client):
    assert client.get(api.url_for(Authorities, authority_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_authority_post(client):
    assert client.post(api.url_for(Authorities, authority_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_put(client):
    assert client.put(api.url_for(Authorities, authority_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_authority_delete(client):
    assert client.delete(api.url_for(Authorities, authority_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_patch(client):
    assert client.patch(api.url_for(Authorities, authority_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authorities_get(client):
    assert client.get(api.url_for(AuthoritiesList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_authorities_post(client):
    assert client.post(api.url_for(AuthoritiesList), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_authorities_put(client):
    assert client.put(api.url_for(AuthoritiesList), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authorities_delete(client):
    assert client.delete(api.url_for(AuthoritiesList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_authorities_get(client):
    assert client.get(api.url_for(CertificateAuthority, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 404


def test_admin_certificate_authorities_post(client):
    assert client.post(api.url_for(CertificateAuthority, certficate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_authorities_put(client):
    assert client.put(api.url_for(CertificateAuthority, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_authorities_delete(client):
    assert client.delete(api.url_for(CertificateAuthority, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405
