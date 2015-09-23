"""
.. module: lemur.domains.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.domains.models import Domain
from lemur.certificates.models import Certificate

from lemur import database


def get(domain_id):
    """
    Fetches one domain

    :param domain_id:
    :return:
    """
    return database.get(Domain, domain_id)


def get_all():
    """
    Fetches all domains

    :return:
    """
    query = database.session_query(Domain)
    return database.find_all(query, Domain, {}).all()


def render(args):
    """
    Helper to parse REST Api requests

    :param args:
    :return:
    """
    query = database.session_query(Domain).join(Certificate, Domain.certificate)

    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Domain, terms)

    if certificate_id:
        query = query.filter(Certificate.id == certificate_id)

    query = database.find_all(query, Domain, args)

    if sort_by and sort_dir:
        query = database.sort(query, Domain, sort_by, sort_dir)

    return database.paginate(query, page, count)
