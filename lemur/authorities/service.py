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
from typing import Optional

from flask import current_app

from lemur import database
from lemur.common.utils import truthiness, data_encrypt
from lemur.extensions import metrics
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.roles import service as role_service
from lemur.logs import service as log_service

from lemur.certificates.service import upload


def update(authority_id, description, owner, active, roles, options: Optional[str] = None):
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
    if options:
        authority.options = options

    log_service.audit_log("update_authority", authority.name, "Updating authority")  # check ui what can be updated
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

    # Check body for root cert
    if values[0] is None:
        raise ValueError(f"Plugin '{issuer.get_title()}' provided no root certification. Check plugin configuration.")

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

    log_service.audit_log("create_authority_with_issuer", issuer.title, "Created new authority")
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
        # error out if the role already exists, because we want a unique role per authority
        if role:
            raise Exception("Unable to create authority role {} because it already exists".format(r["name"]))
        role = role_service.create(
            r["name"],
            password=r["password"],
            description=f"Auto generated role for {plugin_title}",
            username=r["username"],
        )

        role_objs.append(role)

    # get or create a role for the owner
    owner_role = role_service.get_by_name(owner)
    if not owner_role:
        owner_role = role_service.create(
            owner, description=f"Auto generated role based on owner: {owner}"
        )

    role_objs.append(owner_role)
    return role_objs


def create(**kwargs):
    """
    Creates a new authority.
    """
    ca_name = kwargs.get("name")
    if get_by_name(ca_name):
        raise Exception(f"Authority with name {ca_name} already exists")
    if role_service.get_by_name(f"{ca_name}_admin") or role_service.get_by_name(f"{ca_name}_operator"):
        raise Exception(f"Admin and/or operator roles for authority {ca_name} already exist")

    body, private_key, chain, roles = mint(**kwargs)

    kwargs["body"] = body
    kwargs["private_key"] = private_key
    kwargs["chain"] = chain

    if not kwargs.get("roles"):
        kwargs["roles"] = []
    kwargs["roles"] += [role for role in roles if role not in kwargs["roles"]]

    cert = upload(**kwargs)
    kwargs["authority_certificate"] = cert
    if kwargs.get("plugin", {}).get("plugin_options", []):
        # encrypt the private key before persisting in DB
        for option in kwargs.get("plugin").get("plugin_options"):
            if option["name"] == "acme_private_key" and option["value"]:
                option["value"] = data_encrypt(option["value"])
        kwargs["options"] = json.dumps(kwargs["plugin"]["plugin_options"])

    authority = Authority(**kwargs)
    authority = database.create(authority)
    kwargs["creator"].authorities.append(authority)

    log_service.audit_log("create_authority", ca_name, "Created new authority")

    issuer = kwargs["plugin"]["plugin_object"]
    current_app.logger.warning(f"Created new authority {ca_name} with issuer {issuer.title}")

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


def get_authorities_by_name(authority_names):
    """
    Retrieves an authority given it's name.

    :param authority_names: list with authority names to match
    :return:
    """
    return Authority.query.filter(Authority.name.in_(authority_names)).all()


def get_authority_role(ca_name, creator=None):
    """
    Attempts to get the authority role for a given ca uses current_user
    as a basis for accomplishing that.

    :param ca_name:
    """
    if creator:
        if creator.is_admin:
            return role_service.get_by_name(f"{ca_name}_admin")
    return role_service.get_by_name(f"{ca_name}_operator")


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
            term = f"%{terms[1]}%"
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
