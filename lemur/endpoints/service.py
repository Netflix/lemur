"""
.. module: lemur.endpoints.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer endpoints in Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import g

from lemur import database
from lemur.extensions import metrics
from lemur.endpoints.models import Endpoint, Policy


def get_all():
    """
    Get all endpoints that are currently in Lemur.

    :rtype : List
    :return:
    """
    query = database.session_query(Endpoint)
    return database.find_all(query, Endpoint, {}).all()


def get(endpoint_id):
    """
    Retrieves an endpoint given it's ID

    :param endpoint_id:
    :return:
    """
    return database.get(Endpoint, endpoint_id)


def get_by_dnsname(endpoint_dnsname):
    """
    Retrieves an endpoint given it's name.

    :param endpoint_dnsname:
    :return:
    """
    return database.get(Endpoint, endpoint_dnsname, field='dnsname')


def create(**kwargs):
    """
    Creates a new endpoint.
    :param kwargs:
    :return:
    """
    endpoint = Endpoint(**kwargs)
    database.create(endpoint)
    metrics.send('endpoint_added', 'counter', 1)
    return endpoint


def create_policy(**kwargs):
    policy = Policy(**kwargs)
    database.create(policy)
    return policy


def update(endpoint_id, **kwargs):
    endpoint = database.get(Endpoint, endpoint_id)

    endpoint.policy = kwargs['policy']
    endpoint.certificate = kwargs['certificate']
    database.update(endpoint)
    return endpoint


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(Endpoint)
    filt = args.pop('filter')

    if filt:
        terms = filt.split(';')
        if 'active' in filt:  # this is really weird but strcmp seems to not work here??
            query = query.filter(Endpoint.active == terms[1])
        else:
            query = database.filter(query, Endpoint, terms)

    # we make sure that a user can only use an endpoint they either own are are a member of - admins can see all
    if not g.current_user.is_admin:
        endpoint_ids = []
        for role in g.current_user.roles:
            for endpoint in role.endpoints:
                endpoint_ids.append(endpoint.id)
        query = query.filter(Endpoint.id.in_(endpoint_ids))

    return database.sort_and_page(query, Endpoint, args)
