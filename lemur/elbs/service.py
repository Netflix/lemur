"""
.. module: lemur.elbs.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import func
from sqlalchemy.sql import and_

from lemur import database
from lemur.elbs.models import ELB
from lemur.listeners.models import Listener

def get_all(account_id, elb_name):
    """
    Retrieves all ELBs in a given account

    :param account_id:
    :param elb_name:
    :rtype : Elb
    :return:
    """
    query = database.session_query(ELB)
    return query.filter(and_(ELB.name == elb_name, ELB.account_id == account_id)).all()


def get_by_region_and_account(region, account_id):
    query = database.session_query(ELB)
    return query.filter(and_(ELB.region == region, ELB.account_id == account_id)).all()


def get_all_elbs():
    """
    Get all ELBs that Lemur knows about

    :rtype : list
    :return:
    """
    return ELB.query.all()


def get(elb_id):
    """
    Retrieve an ELB with a give ID

    :rtype : Elb
    :param elb_id:
    :return:
    """
    return database.get(ELB, elb_id)


def create(account, elb):
    """
    Create a new ELB

    :param account:
    :param elb:
    """
    elb = ELB(elb)
    account.elbs.append(elb)
    database.create(elb)


def delete(elb_id):
    """
    Delete an ELB

    :param elb_id:
    """
    database.delete(get(elb_id))


def render(args):
    query = database.session_query(ELB)

    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    active = args.pop('active')
    certificate_id = args.pop('certificate_id')

    if certificate_id:
        query.filter(ELB.listeners.any(Listener.certificate_id == certificate_id))

    if active == 'true':
        query = query.filter(ELB.listeners.any())

    if filt:
        terms = filt.split(';')
        query = database.filter(query, ELB, terms)

    query = database.find_all(query, ELB, args)

    if sort_by and sort_dir:
        query = database.sort(query, ELB, sort_by, sort_dir)

    return database.paginate(query, page, count)


def stats(**kwargs):
    attr = getattr(ELB, kwargs.get('metric'))
    query = database.db.session.query(attr, func.count(attr))

    if kwargs.get('account_id'):
        query = query.filter(ELB.account_id == kwargs.get('account_id'))

    if kwargs.get('active') == 'true':
        query = query.join(ELB.listeners)
        query = query.filter(Listener.certificate_id != None)

    items = query.group_by(attr).all()

    results = []
    for key, count in items:
        if key:
            results.append({"key": key, "y": count})
    return results


