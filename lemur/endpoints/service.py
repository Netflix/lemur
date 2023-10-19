"""
.. module: lemur.endpoints.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer endpoints in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import arrow

from sqlalchemy import func
from sqlalchemy.orm import joinedload

from lemur import database
from lemur.common.utils import truthiness
from lemur.endpoints.models import Endpoint, EndpointDnsAlias, Policy, Cipher
from lemur.sources.models import Source
from lemur.extensions import metrics


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


def get_by_name(name):
    """
    Retrieves an endpoint given it's name.

    :param name:
    :return:
    """
    return database.get(Endpoint, name, field="name")


def get_by_name_and_source(name, source):
    """
    Retrieves an endpoint by it's name and source.
    :param name:
    :param source:
    :return:
    """
    return (
        database.session_query(Endpoint)
        .filter(Endpoint.name == name)
        .filter(Endpoint.source.has(Source.label == source))
        .scalar()
    )


def get_by_dnsname(dnsname):
    """
    Retrieves an endpoint given it's name.

    :param dnsname:
    :return:
    """
    return database.get(Endpoint, dnsname, field="dnsname")


def get_by_dnsname_and_port(dnsname, port):
    """
    Retrieves and endpoint by it's dnsname and port.
    :param dnsname:
    :param port:
    :return:
    """
    return (
        Endpoint.query.filter(Endpoint.dnsname == dnsname)
        .filter(Endpoint.port == port)
        .scalar()
    )


def get_by_source(source_label):
    """
    Retrieves all endpoints for a given source.
    :param source_label:
    :return:
    """
    return Endpoint.query.filter(Endpoint.source.label == source_label).all()  # noqa


def get_all_pending_rotation():
    """
    Retrieves all endpoints which have certificates deployed
    that have been replaced.
    :return:
    """
    return Endpoint.query.filter(Endpoint.replaced.any()).all()


def create(**kwargs):
    """
    Creates a new endpoint.
    :param kwargs:
    :return:
    """
    aliases = []
    if "aliases" in kwargs:
        aliases = [EndpointDnsAlias(alias=name) for name in kwargs.pop("aliases")]
    endpoint = Endpoint(**kwargs)
    endpoint.aliases = aliases
    database.create(endpoint)
    metrics.send(
        "endpoint_added", "counter", 1,
        metric_tags={"source": endpoint.source.label, "type": endpoint.type}
    )
    return endpoint


def get_or_create_policy(**kwargs):
    policy = database.get(Policy, kwargs["name"], field="name")

    if not policy:
        policy = Policy(**kwargs)
        database.create(policy)

    return policy


def get_or_create_cipher(**kwargs):
    cipher = database.get(Cipher, kwargs["name"], field="name")

    if not cipher:
        cipher = Cipher(**kwargs)
        database.create(cipher)

    return cipher


def update(endpoint_id, **kwargs):
    endpoint = database.get(Endpoint, endpoint_id)

    endpoint.policy = kwargs["policy"]
    endpoint.certificate = kwargs["certificate"]
    endpoint.source = kwargs["source"]
    endpoint.certificate_path = kwargs.get("certificate_path")
    endpoint.registry_type = kwargs.get("registry_type")
    existing_alias = {}
    for e in endpoint.aliases:
        existing_alias[e.alias] = e
    endpoint.aliases = []
    if "aliases" in kwargs:
        for name in kwargs["aliases"]:
            if name in existing_alias:
                endpoint.aliases.append(existing_alias[name])
            else:
                endpoint.aliases.append(EndpointDnsAlias(alias=name))
    endpoint.last_updated = arrow.utcnow()
    metrics.send(
        "endpoint_updated", "counter", 1,
        metric_tags={"source": endpoint.source.label, "type": endpoint.type}
    )
    database.update(endpoint)
    return endpoint


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(Endpoint)\
        .options(joinedload(Endpoint.certificate))\
        .options(joinedload(Endpoint.source))
    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        term = f"%{terms[1]}%"
        if "active" in filt:  # this is really weird but strcmp seems to not work here??
            query = query.filter(Endpoint.active == truthiness(terms[1]))
        elif "port" in filt:
            if terms[1] != "null":  # ng-table adds 'null' if a number is removed
                query = query.filter(Endpoint.port == terms[1])
        elif "ciphers" in filt:
            query = query.filter(Cipher.name == terms[1])
        elif "source" in filt:
            query = query.filter(Endpoint.source.has(Source.label.like(term.lower())))
        else:
            query = database.filter(query, Endpoint, terms)

        if terms[0] == "name":
            alias_query = Endpoint.query.filter(
                Endpoint.aliases.any(EndpointDnsAlias.alias.ilike(f"%{terms[1]}%")))
            query = query.union(alias_query)

    return database.sort_and_page(query, Endpoint, args)


def stats(**kwargs):
    """
    Helper that defines some useful statistics about endpoints.

    :param kwargs:
    :return:
    """
    attr = getattr(Endpoint, kwargs.get("metric"))
    query = database.db.session.query(attr, func.count(attr))

    items = query.group_by(attr).all()

    keys = []
    values = []
    for key, count in items:
        keys.append(key)
        values.append(count)

    return {"labels": keys, "values": values}
