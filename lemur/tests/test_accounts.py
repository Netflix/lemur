from lemur.accounts.service import *
from lemur.accounts.views import *

from json import dumps


def test_crud(session):
    account = create('111111', 'account1')
    assert account.id > 0

    account = update(account.id, 11111, 'account2')
    assert account.label == 'account2'

    assert len(get_all()) == 1

    delete(1)
    assert len(get_all()) == 0


def test_account_get(client):
    assert client.get(api.url_for(Accounts, account_id=1)).status_code == 401


def test_account_post(client):
    assert client.post(api.url_for(Accounts, account_id=1), data={}).status_code == 405


def test_account_put(client):
    assert client.put(api.url_for(Accounts, account_id=1), data={}).status_code == 401


def test_account_delete(client):
    assert client.delete(api.url_for(Accounts, account_id=1)).status_code == 401


def test_account_patch(client):
    assert client.patch(api.url_for(Accounts, account_id=1), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}

def test_auth_account_get(client):
    assert client.get(api.url_for(Accounts, account_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_account_post_(client):
    assert client.post(api.url_for(Accounts, account_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_account_put(client):
    assert client.put(api.url_for(Accounts, account_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_account_delete(client):
    assert client.delete(api.url_for(Accounts, account_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_auth_account_patch(client):
    assert client.patch(api.url_for(Accounts, account_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}

def test_admin_account_get(client):
    assert client.get(api.url_for(Accounts, account_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_account_post(client):
    assert client.post(api.url_for(Accounts, account_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_account_put(client):
    assert client.put(api.url_for(Accounts, account_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_account_delete(client):
    assert client.delete(api.url_for(Accounts, account_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 500


def test_admin_account_patch(client):
    assert client.patch(api.url_for(Accounts, account_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_accounts_get(client):
    assert client.get(api.url_for(AccountsList)).status_code == 401


def test_accounts_post(client):
    assert client.post(api.url_for(AccountsList), data={}).status_code == 401


def test_accounts_put(client):
    assert client.put(api.url_for(AccountsList), data={}).status_code == 405


def test_accounts_delete(client):
    assert client.delete(api.url_for(AccountsList)).status_code == 405


def test_accounts_patch(client):
    assert client.patch(api.url_for(AccountsList), data={}).status_code == 405


def test_auth_accounts_get(client):
    assert client.get(api.url_for(AccountsList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_accounts_post(client):
    assert client.post(api.url_for(AccountsList), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 403


def test_admin_accounts_get(client):
    resp = client.get(api.url_for(AccountsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}


def test_admin_accounts_crud(client):
    assert client.post(api.url_for(AccountsList), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400
    data = {'accountNumber': 111, 'label': 'test', 'comments': 'test'}
    resp = client.post(api.url_for(AccountsList), data=dumps(data), content_type='application/json',  headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert client.get(api.url_for(Accounts, account_id=resp.json['id']), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(AccountsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [{'accountNumber': 111, 'label': 'test', 'comments': 'test', 'id': 2}], 'total': 1}
    assert client.delete(api.url_for(Accounts, account_id=2), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
    resp = client.get(api.url_for(AccountsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}
