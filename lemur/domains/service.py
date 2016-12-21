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


def get_by_name(name):
    """
    Fetches domain by its name

    :param name:
    :return:
    """
    return database.get_all(Domain, name, field="name").all()


def create(name, sensitive):
    """
    Create a new domain

    :param name:
    :param sensitive:
    :return:
    """
    domain = Domain(name=name, sensitive=sensitive)
    return database.create(domain)


def update(domain_id, name, sensitive):
    """
    Update an existing domain

    :param domain_id:
    :param name:
    :param sensitive:
    :return:
    """
    domain = get(domain_id)
    domain.name = name
    domain.sensitive = sensitive
    database.update(domain)


def render(args):
    """
    Helper to parse REST Api requests

    :param args:
    :return:
    """
    query = database.session_query(Domain).join(Certificate, Domain.certificate)
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Domain, terms)

    if certificate_id:
        query = query.filter(Certificate.id == certificate_id)

    return database.sort_and_page(query, Domain, args)
