"""
.. module: lemur.domains.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import and_

from flask import current_app, g

from lemur import database
from lemur.certificates.models import Certificate
from lemur.domains.models import Domain
from lemur.plugins.base import plugins
from lemur.plugins.bases.authorization import UnauthorizedError


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


def is_domain_sensitive(name):
    """
    Return True if domain is marked sensitive

    :param name:
    :return:
    """
    query = database.session_query(Domain)

    query = query.filter(and_(Domain.sensitive, Domain.name == name))

    return database.find_all(query, Domain, {}).all()


def is_authorized_for_domain(name):
    """
    If authorization plugin is available, perform the check to see if current user can issue certificate for a given
    domain.
    Raises UnauthorizedError if unauthorized.
    If authorization plugin is not available, it returns without performing any check

    :param name: domain (string) for which authorization check is being done
    """
    if current_app.config.get("USER_DOMAIN_AUTHORIZATION_PROVIDER") is None:
        # nothing to check since USER_DOMAIN_AUTHORIZATION_PROVIDER is not configured
        return

    user_domain_authorization_provider = plugins.get(current_app.config.get("USER_DOMAIN_AUTHORIZATION_PROVIDER"))
    # if the caller can be mapped to an application name, use that to perform authorization
    # this could be true when using API key to call lemur (migration script e2d406ada25c_.py)
    caller = g.caller_application if hasattr(g, 'caller_application') else g.user.email
    authorized, error = user_domain_authorization_provider.is_authorized(domain=name, caller=caller)

    if error:
        raise error
    if not authorized:
        raise UnauthorizedError(user=caller, resource=name, action="issue_certificate")


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
    query = database.session_query(Domain)
    filt = args.pop("filter")
    certificate_id = args.pop("certificate_id", None)

    if filt:
        terms = filt.split(";")
        query = database.filter(query, Domain, terms)

    if certificate_id:
        query = query.join(Certificate, Domain.certificates)
        query = query.filter(Certificate.id == certificate_id)

    return database.sort_and_page(query, Domain, args)
