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
from lemur.endpoints.models import Endpoint


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


def get_by_name(endpoint_name):
    """
    Retrieves an endpoint given it's name.

    :param endpoint_name:
    :return:
    """
    return database.get(Endpoint, endpoint_name, field='name')


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
