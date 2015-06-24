
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

    assert client.get(api.url_for(AccountsList)).status_code == 401
    assert client.post(api.url_for(AccountsList), {}).status_code == 401
    assert client.put(api.url_for(AccountsList), {}).status_code == 405
    assert client.delete(api.url_for(AccountsList)).status_code == 405
    assert client.patch(api.url_for(Accounts), {}).status_code == 405

    assert client.get(api.url_for(CertificateAccounts, certificate_id=1)).status_code == 401
    assert client.post(api.url_for(CertificateAccounts), {}).status_code == 405
    assert client.put(api.url_for(CertificateAccounts), {}).status_code == 405
    assert client.delete(api.url_for(CertificateAccounts)).status_code == 405
    assert client.patch(api.url_for(CertificateAccounts), {}).status_code == 405
