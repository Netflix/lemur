"""
.. module: service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer roles in Lemur

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from lemur import database
from lemur.roles.models import Role
from lemur.users.models import User
from lemur.logs import service as log_service


def warn_user_updates(role_name, current_users, new_users):
    removed_users = list(u.username for u in set(current_users) - set(new_users))
    if removed_users:
        current_app.logger.warning(f"Removed {role_name} role for {removed_users}")

    added_users = list(u.username for u in set(new_users) - set(current_users))
    if added_users:
        current_app.logger.warning(f"Added {role_name} role for {added_users}")


def update(role_id, name, description, users):
    """
    Update a role

    :param role_id:
    :param name:
    :param description:
    :param users:
    :return:
    """
    role = get(role_id)

    if name == 'admin':
        warn_user_updates(name, role.users, users)
    role.name = name
    role.description = description
    role.users = users
    database.update(role)

    log_service.audit_log("update_role", name, f"Role with id {role_id} updated")
    return role


def set_third_party(role_id, third_party_status=False):
    """
    Sets a role to be a third party role. A user should pretty much never
    call this directly.

    :param role_id:
    :param third_party_status:
    :return:
    """
    role = get(role_id)
    role.third_party = third_party_status
    database.update(role)

    log_service.audit_log("update_role", role.name, f"Updated third_party_status={third_party_status}")
    return role


def create(
    name, password=None, description=None, username=None, users=None, third_party=False
):
    """
    Create a new role

    :param name:
    :param users:
    :param description:
    :param username:
    :param password:
    :return:
    """
    role = Role(
        name=name,
        description=description,
        username=username,
        password=password,
        third_party=third_party,
    )

    if users:
        role.users = users

    log_service.audit_log("create_role", name, "Creating new role")
    return database.create(role)


def get(role_id):
    """
    Retrieve a role by ID

    :param role_id:
    :return:
    """
    return database.get(Role, role_id)


def get_by_name(role_name):
    """
    Retrieve a role by its name

    :param role_name:
    :return:
    """
    return database.get(Role, role_name, field="name")


def delete(role_id):
    """
    Remove a role

    :param role_id:
    :return:
    """

    role = get(role_id)
    log_service.audit_log("delete_role", role.name, "Deleting role")
    return database.delete(role)


def render(args):
    """
    Helper that filters subsets of roles depending on the parameters
    passed to the REST Api

    :param args:
    :return:
    """
    query = database.session_query(Role)
    filt = args.pop("filter")
    user_id = args.pop("user_id", None)
    authority_id = args.pop("authority_id", None)

    if user_id:
        query = query.filter(Role.users.any(User.id == user_id))

    if authority_id:
        query = query.filter(Role.authority_id == authority_id)

    if filt:
        terms = filt.split(";")
        query = database.filter(query, Role, terms)

    return database.sort_and_page(query, Role, args)


def get_or_create(role_name, description):
    role = get_by_name(role_name)
    if not role:
        role = create(name=role_name, description=description)

    return role
