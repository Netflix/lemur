"""
.. module: lemur.authorities.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer authorities in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""

import json

from lemur import database
from lemur.common.utils import truthiness
from lemur.extensions import metrics
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.roles import service as role_service

from lemur.certificates.service import upload


def update(authority_id, description, owner, active, roles):
    """
    Update an authority with new values.

    :param authority_id:
    :param roles: roles that are allowed to use this authority
    :return:
    """
    authority = get(authority_id)

    authority.roles = roles
    authority.active = active
    authority.description = description
    authority.owner = owner

    return database.update(authority)


def update_options(authority_id, options):
    """
    Update an authority with new options.

    :param authority_id:
    :param options: the new options to be saved into the authority
    :return:
    """

    authority = get(authority_id)

    authority.options = options

    return database.update(authority)

def mint(**kwargs):
    """
    Creates the authority based on the plugin provided.
    """
    issuer = kwargs["plugin"]["plugin_object"]
    values = issuer.create_authority(kwargs)

    # support older plugins
    if len(values) == 3:
        body, chain, roles = values
        private_key = None
    elif len(values) == 4:
        body, private_key, chain, roles = values

    roles = create_authority_roles(
        roles,
        kwargs["owner"],
        kwargs["plugin"]["plugin_object"].title,
        kwargs["creator"],
    )
    return body, private_key, chain, roles


def create_authority_roles(roles, owner, plugin_title, creator):
    """
    Creates all of the necessary authority roles.
    :param creator:
    :param roles:
    :return:
    """
    role_objs = []
    for r in roles:
        role = role_service.get_by_name(r["name"])
        if not role:
            role = role_service.create(
                r["name"],
                password=r["password"],
                description="Auto generated role for {0}".format(plugin_title),
                username=r["username"],
            )

        # the user creating the authority should be able to administer it
        if role.username == "admin":
            creator.roles.append(role)

        role_objs.append(role)

    # create an role for the owner and assign it
    owner_role = role_service.get_by_name(owner)
    if not owner_role:
        owner_role = role_service.create(
            owner, description="Auto generated role based on owner: {0}".format(owner)
        )

    role_objs.append(owner_role)
    return role_objs


def create(**kwargs):
    """
    Creates a new authority.
    """
    body, private_key, chain, roles = mint(**kwargs)

    kwargs["creator"].roles = list(set(list(kwargs["creator"].roles) + roles))

    kwargs["body"] = body
    kwargs["private_key"] = private_key
    kwargs["chain"] = chain

    if kwargs.get("roles"):
        kwargs["roles"] += roles
    else:
        kwargs["roles"] = roles

    cert = upload(**kwargs)
    kwargs["authority_certificate"] = cert
    if kwargs.get("plugin", {}).get("plugin_options", []):
        kwargs["options"] = json.dumps(kwargs["plugin"]["plugin_options"])

    authority = Authority(**kwargs)
    authority = database.create(authority)
    kwargs["creator"].authorities.append(authority)

    metrics.send(
        "authority_created", "counter", 1, metric_tags=dict(owner=authority.owner)
    )
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
    return database.get(Authority, authority_name, field="name")


def get_authority_role(ca_name, creator=None):
    """
    Attempts to get the authority role for a given ca uses current_user
    as a basis for accomplishing that.

    :param ca_name:
    """
    if creator:
        if creator.is_admin:
            return role_service.get_by_name("{0}_admin".format(ca_name))
    return role_service.get_by_name("{0}_operator".format(ca_name))


def render(args):
    """
    Helper that helps us render the REST Api responses.
    :param args:
    :return:
    """
    query = database.session_query(Authority)
    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        if "active" in filt:
            query = query.filter(Authority.active == truthiness(terms[1]))
        elif "cn" in filt:
            term = "%{0}%".format(terms[1])
            sub_query = (
                database.session_query(Certificate.root_authority_id)
                .filter(Certificate.cn.ilike(term))
                .subquery()
            )

            query = query.filter(Authority.id.in_(sub_query))
        else:
            query = database.filter(query, Authority, terms)

    # we make sure that a user can only use an authority they either own are a member of - admins can see all
    if not args["user"].is_admin:
        authority_ids = []
        for authority in args["user"].authorities:
            authority_ids.append(authority.id)

        for role in args["user"].roles:
            for authority in role.authorities:
                authority_ids.append(authority.id)
        query = query.filter(Authority.id.in_(authority_ids))

    return database.sort_and_page(query, Authority, args)
