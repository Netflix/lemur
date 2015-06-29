from json import dumps
from lemur.roles.service import *
from lemur.roles.views import *


def test_crud(session):
    role = create('role1')
    assert role.id > 0

    role = update(role.id, 'role_new', None, [])
    assert role.name == 'role_new'
    delete(role.id)
    assert get(role.id) == None


def test_role_get(client):
    assert client.get(api.url_for(Roles, role_id=1)).status_code == 401


def test_role_post(client):
    assert client.post(api.url_for(Roles, role_id=1), {}).status_code == 405


def test_role_put(client):
    assert client.put(api.url_for(Roles, role_id=1), {}).status_code == 401


def test_role_delete(client):
    assert client.delete(api.url_for(Roles, role_id=1)).status_code == 401


def test_role_patch(client):
    assert client.patch(api.url_for(Roles, role_id=1), {}).status_code == 405


def test_roles_get(client):
    assert client.get(api.url_for(RolesList)).status_code == 401


def test_roles_post(client):
    assert client.post(api.url_for(RolesList), {}).status_code == 401


def test_roles_put(client):
    assert client.put(api.url_for(RolesList), {}).status_code == 405


def test_roles_delete(client):
    assert client.delete(api.url_for(RolesList)).status_code == 405


def test_roles_patch(client):
    assert client.patch(api.url_for(RolesList), {}).status_code == 405


def test_role_credentials_get(client):
    assert client.get(api.url_for(RoleViewCredentials, role_id=1)).status_code == 401


def test_role_credentials_post(client):
    assert client.post(api.url_for(RoleViewCredentials, role_id=1), {}).status_code == 405


def test_role_credentials_put(client):
    assert client.put(api.url_for(RoleViewCredentials, role_id=1), {}).status_code == 405


def test_role_credentials_delete(client):
    assert client.delete(api.url_for(RoleViewCredentials, role_id=1)).status_code == 405


def test_role_credentials_patch(client):
    assert client.patch(api.url_for(RoleViewCredentials, role_id=1), {}).status_code == 405


def test_user_roles_get(client):
    assert client.get(api.url_for(UserRolesList, user_id=1)).status_code == 401


def test_user_roles_post(client):
    assert client.post(api.url_for(UserRolesList, user_id=1), {}).status_code == 405


def test_user_roles_put(client):
    assert client.put(api.url_for(UserRolesList, user_id=1), {}).status_code == 405


def test_user_roles_delete(client):
    assert client.delete(api.url_for(UserRolesList, user_id=1)).status_code == 405


def test_user_roles_patch(client):
    assert client.patch(api.url_for(UserRolesList, user_id=1), {}).status_code == 405


def test_authority_roles_get(client):
    assert client.get(api.url_for(AuthorityRolesList, authority_id=1)).status_code == 401


def test_authority_roles_post(client):
    assert client.post(api.url_for(AuthorityRolesList, authority_id=1), {}).status_code == 405


def test_authority_roles_put(client):
    assert client.put(api.url_for(AuthorityRolesList, authority_id=1), {}).status_code == 405


def test_authority_roles_delete(client):
    assert client.delete(api.url_for(AuthorityRolesList, authority_id=1)).status_code == 405


def test_authority_roles_patch(client):
    assert client.patch(api.url_for(AuthorityRolesList, authority_id=1), {}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_role_get(client):
    assert client.get(api.url_for(Roles, role_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_role_post_(client):
    assert client.post(api.url_for(Roles, role_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_role_put(client):
    assert client.put(api.url_for(Roles, role_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_role_delete(client):
    assert client.delete(api.url_for(Roles, role_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_role_patch(client):
    assert client.patch(api.url_for(Roles, role_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_roles_get(client):
    assert client.get(api.url_for(RolesList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_roles_post(client):
    assert client.post(api.url_for(RolesList), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_role_credentials_get(client):
    assert client.get(api.url_for(RoleViewCredentials, role_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_role_credentials_post(client):
    assert client.post(api.url_for(RoleViewCredentials, role_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_role_credentials_put(client):
    assert client.put(api.url_for(RoleViewCredentials, role_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_role_credentials_delete(client):
    assert client.delete(api.url_for(RoleViewCredentials, role_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_role_credentials_patch(client):
    assert client.patch(api.url_for(RoleViewCredentials, role_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_user_roles_get(client):
    assert client.get(api.url_for(UserRolesList, user_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_user_roles_post(client):
    assert client.post(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_user_roles_put(client):
    assert client.put(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_user_roles_delete(client):
    assert client.delete(api.url_for(UserRolesList, user_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_user_roles_patch(client):
    assert client.patch(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_roles_get(client):
    assert client.get(api.url_for(AuthorityRolesList, authority_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_authority_roles_post(client):
    assert client.post(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_roles_put(client):
    assert client.put(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_roles_delete(client):
    assert client.delete(api.url_for(AuthorityRolesList, authority_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_authority_roles_patch(client):
    assert client.patch(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_role_get(client):
    assert client.get(api.url_for(Roles, role_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_role_post(client):
    assert client.post(api.url_for(Roles, role_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_role_put(client):
    assert client.put(api.url_for(Roles, role_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_role_delete(client):
    assert client.delete(api.url_for(Roles, role_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_role_patch(client):
    assert client.patch(api.url_for(Roles, role_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_roles_get(client):
    resp = client.get(api.url_for(RolesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['total'] > 0


def test_admin_role_credentials_get(client):
    assert client.get(api.url_for(RolesList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_role_credentials_post(client):
    assert client.post(api.url_for(RolesList), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_role_credentials_put(client):
    assert client.put(api.url_for(RolesList), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_role_credentials_delete(client):
    assert client.delete(api.url_for(RolesList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_role_credentials_patch(client):
    assert client.patch(api.url_for(RolesList), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_user_roles_get(client):
    assert client.get(api.url_for(UserRolesList, user_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_user_roles_post(client):
    assert client.post(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_user_roles_put(client):
    assert client.put(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_user_roles_delete(client):
    assert client.delete(api.url_for(UserRolesList, user_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_user_roles_patch(client):
    assert client.patch(api.url_for(UserRolesList, user_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_roles_get(client):
    assert client.get(api.url_for(AuthorityRolesList, authority_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_authority_roles_post(client):
    assert client.post(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_roles_put(client):
    assert client.put(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_roles_delete(client):
    assert client.delete(api.url_for(AuthorityRolesList, authority_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_authority_roles_patch(client):
    assert client.patch(api.url_for(AuthorityRolesList, authority_id=1), {}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_roles_crud(client):
    assert client.post(api.url_for(RolesList), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400
    data = {'name': 'role', 'description': 'test'}
    resp = client.post(api.url_for(RolesList), data=dumps(data), content_type='application/json', headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    role_id = resp.json['id']
    assert client.get(api.url_for(Roles, role_id=role_id), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(RolesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['total'] == 2
    assert client.delete(api.url_for(Roles, role_id=role_id), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(RolesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['total'] == 1
