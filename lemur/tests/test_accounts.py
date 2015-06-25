
import pytest
from lemur.accounts.service import *
from lemur.exceptions import DuplicateError

from lemur.accounts.views import *

#def test_crud(session):
#    account = create('111111', 'account1')
#    assert account.id > 0
#
#    account = update(account.id, 11111, 'account2')
#    assert account.label == 'account2'
#
#    assert len(get_all()) == 1
#
#    delete(1)
#    assert len(get_all()) == 0
#

#def test_duplicate(session):
#    account = create('111111', 'account1')
#    assert account.id > 0
#
#    with pytest.raises(DuplicateError):
#        account = create('111111', 'account1')


def test_basic_user_views(client):
    pass


def test_admin_user_views(client):
    pass

def test_unauthenticated_views(client):
    assert client.get(api.url_for(Accounts, account_id=1)).status_code == 401
    assert client.post(api.url_for(Accounts, account_id=1), {}).status_code == 405
    assert client.put(api.url_for(Accounts, account_id=1), {}).status_code == 401
    assert client.delete(api.url_for(Accounts, account_id=1)).status_code == 401
    assert client.patch(api.url_for(Accounts, account_id=1), {}).status_code == 405

VALID_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'

def test_auth_account_get(auth_client):
        assert auth_client.get(api.url_for(Accounts, account_id=1), headers={'Authorization': 'Basic ' + VALID_TOKEN}).status_code == 200