"""
.. module: lemur.authorities.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer authorities in Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import g

from lemur import database
from lemur.extensions import metrics
from lemur.authorities.models import Authority
from lemur.roles import service as role_service

from lemur.certificates.service import upload


def update(authority_id, description=None, owner=None, active=None, roles=None):
    """
    Update a an authority with new values.

    :param authority_id:
    :param roles: roles that are allowed to use this authority
    :return:
    """
    authority = get(authority_id)

    if roles:
        authority.roles = roles

    if active:
        authority.active = active

    authority.description = description
    authority.owner = owner
    return database.update(authority)


def mint(**kwargs):
    """
    Creates the authority based on the plugin provided.
    """
    issuer = kwargs['plugin']['plugin_object']
    body, chain, roles = issuer.create_authority(kwargs)
    roles = create_authority_roles(roles, kwargs['owner'], kwargs['plugin']['plugin_object'].title)
    return body, chain, roles


def create_authority_roles(roles, owner, plugin_title):
    """
    Creates all of the necessary authority roles.
    :param roles:
    :return:
    """
    role_objs = []
    for r in roles:
        role = role_service.get_by_name(r['name'])
        if not role:
            role = role_service.create(
                r['name'],
                password=r['password'],
                description="Auto generated role for {0}".format(plugin_title),
                username=r['username'])

        # the user creating the authority should be able to administer it
        if role.username == 'admin':
            g.current_user.roles.append(role)

        role_objs.append(role)

    # create an role for the owner and assign it
    owner_role = role_service.get_by_name(owner)
    if not owner_role:
        owner_role = role_service.create(
            owner,
            description="Auto generated role based on owner: {0}".format(owner)
        )

    role_objs.append(owner_role)
    return role_objs


def create(**kwargs):
    """
    Creates a new authority.
    """
    kwargs['creator'] = g.user.email
    body, chain, roles = mint(**kwargs)

    kwargs['body'] = body
    kwargs['chain'] = chain

    if kwargs.get('roles'):
        kwargs['roles'] += roles
    else:
        kwargs['roles'] = roles

    cert = upload(**kwargs)
    kwargs['authority_certificate'] = cert

    authority = Authority(**kwargs)
    authority = database.create(authority)
    g.user.authorities.append(authority)

    metrics.send('authority_created', 'counter', 1, metric_tags=dict(owner=authority.owner))
    return authority


def get_all():
    """
    Get all authorities that are currently in Lemur.

    :rtype : List
    :return:
    """
    query = database.session_query(Authority)
    return database.find_all(query, Authority, {}).all()


def get(authority_id):
    """
    Retrieves an authority given it's ID

    :param authority_id:
    :return:
    """
    return database.get(Authority, authority_id)


def get_by_name(authority_name):
    """
    Retrieves an authority given it's name.

    :param authority_name:
    :return:
    """
    return database.get(Authority, authority_name, field='name')


def get_authority_role(ca_name):
    """
    Attempts to get the authority role for a given ca uses current_user
    as a basis for accomplishing that.

    :param ca_name:
    """
    if g.current_user.is_admin:
        return role_service.get_by_name("{0}_admin".format(ca_name))
    else:
        return role_service.get_by_name("{0}_operator".format(ca_name))


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(Authority)
    filt = args.pop('filter')

    if filt:
        terms = filt.split(';')
        if 'active' in filt:  # this is really weird but strcmp seems to not work here??
            query = query.filter(Authority.active == terms[1])
        else:
            query = database.filter(query, Authority, terms)

    # we make sure that a user can only use an authority they either own are are a member of - admins can see all
    if not g.current_user.is_admin:
        authority_ids = []
        for role in g.current_user.roles:
            for authority in role.authorities:
                authority_ids.append(authority.id)
        query = query.filter(Authority.id.in_(authority_ids))

    return database.sort_and_page(query, Authority, args)
