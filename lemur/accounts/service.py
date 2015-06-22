"""
.. module: lemur.accounts.views
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.accounts.models import Account
from lemur.certificates.models import Certificate


def create(account_number, label=None, comments=None):
    """
    Creates a new account, that can then be used as a destination for certificates.

    :param account_number: AWS assigned ID
    :param label: Account common name
    :param comments:
    :rtype : Account
    :return: New account
    """
    acct = Account(account_number=account_number, label=label, notes=comments)
    return database.create(acct)


def update(account_id, account_number, label, comments=None):
    """
    Updates an existing account.

    :param account_id:  Lemur assigned ID
    :param account_number: AWS assigned ID
    :param label: Account common name
    :param comments:
    :rtype : Account
    :return:
    """
    account = get(account_id)

    account.account_number = account_number
    account.label = label
    account.notes = comments

    return database.update(account)


def delete(account_id):
    """
    Deletes an account.

    :param account_id: Lemur assigned ID
    """
    database.delete(get(account_id))


def get(account_id):
    """
    Retrieves an account by it's lemur assigned ID.

    :param account_id: Lemur assigned ID
    :rtype : Account
    :return:
    """
    return database.get(Account, account_id)


def get_by_account_number(account_number):
    """
    Retrieves an account by it's amazon assigned ID.

    :rtype : Account
    :param account_number: AWS assigned ID
    :return:
    """
    return database.get(Account, account_number, field='account_number')


def get_all():
    """
    Retrieves all account currently known by Lemur.

    :return:
    """
    query = database.session_query(Account)
    return database.find_all(query, Account, {}).all()


def render(args):
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if certificate_id:
        query = database.session_query(Account).join(Certificate, Account.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Account)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Account, terms)

    query = database.find_all(query, Account, args)

    if sort_by and sort_dir:
        query = database.sort(query, Account, sort_by, sort_dir)

    return database.paginate(query, page, count)

