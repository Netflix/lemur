"""
.. module: lemur.endpoints.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer endpoints in Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import current_app

from lemur import database
from lemur.extensions import metrics
from lemur.endpoints.models import Endpoint, Policy, Cipher

from sqlalchemy import func


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


def get_by_source(source_label):
    """
    Retrieves all endpoints for a given source.
    :param source_label:
    :return:
    """
    return Endpoint.query.filter(Endpoint.source.label == source_label).all()  # noqa


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


def get_or_create_policy(**kwargs):
    policy = database.get(Policy, kwargs['name'], field='name')

    if not policy:
        policy = Policy(**kwargs)
        database.create(policy)

    return policy


def get_or_create_cipher(**kwargs):
    cipher = database.get(Cipher, kwargs['name'], field='name')

    if not cipher:
        cipher = Cipher(**kwargs)
        database.create(cipher)

    return cipher


def update(endpoint_id, **kwargs):
    endpoint = database.get(Endpoint, endpoint_id)

    endpoint.policy = kwargs['policy']
    endpoint.certificate = kwargs['certificate']
    endpoint.source = kwargs['source']
    metrics.send('endpoint_added', 'counter', 1)
    database.update(endpoint)
    return endpoint


def rotate_certificate(endpoint, new_cert):
    """Rotates a certificate on a given endpoint."""
    try:
        endpoint.source.plugin.update_endpoint(endpoint, new_cert)
        endpoint.certificate = new_cert
        database.update(endpoint)
    except Exception as e:
        metrics.send('rotate_failure', 'counter', 1, metric_tags={'endpoint': endpoint.name})
        current_app.logger.exception(e)
        raise e


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
        elif 'port' in filt:
            if terms[1] != 'null':  # ng-table adds 'null' if a number is removed
                query = query.filter(Endpoint.port == terms[1])
        elif 'ciphers' in filt:
            query = query.filter(
                Cipher.name == terms[1]
            )
        else:
            query = database.filter(query, Endpoint, terms)

    return database.sort_and_page(query, Endpoint, args)


def stats(**kwargs):
    """
    Helper that defines some useful statistics about endpoints.

    :param kwargs:
    :return:
    """
    attr = getattr(Endpoint, kwargs.get('metric'))
    query = database.db.session.query(attr, func.count(attr))

    items = query.group_by(attr).all()

    keys = []
    values = []
    for key, count in items:
        keys.append(key)
        values.append(count)

    return {'labels': keys, 'values': values}
