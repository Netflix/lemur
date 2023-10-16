"""
.. module: lemur.users.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer users in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from lemur import database
from lemur.logs import service as log_service
from lemur.users.models import User

STRICT_ENFORCEMENT_DEFAULT_ROLES = ["admin", "operator", "read-only"]


def create(username, password, email, active, profile_picture, roles):
    """
    Create a new user

    :param username:
    :param password:
    :param email:
    :param active:
    :param profile_picture:
    :param roles:
    :return:
    """
    strict_role_enforcement = current_app.config.get("LEMUR_STRICT_ROLE_ENFORCEMENT", False)
    if strict_role_enforcement and not any(role.name in STRICT_ENFORCEMENT_DEFAULT_ROLES for role in roles):
        return dict(message="Default role required, user needs least one of the following roles assigned: admin, "
                            "operator, read-only"), 400

    user = User(
        password=password,
        username=username,
        email=email,
        active=active,
        profile_picture=profile_picture,
    )
    user.roles = roles
    log_service.audit_log("create_user", username, "Creating new user")
    return database.create(user)


def update(user_id, username, email, active, profile_picture, roles, password=None):
    """
    Updates an existing user

    :param user_id:
    :param username:
    :param email:
    :param active:
    :param profile_picture:
    :param roles:
    :param password:
    :return:
    """
    strict_role_enforcement = current_app.config.get("LEMUR_STRICT_ROLE_ENFORCEMENT", False)
    if strict_role_enforcement and not any(role.name in STRICT_ENFORCEMENT_DEFAULT_ROLES for role in roles):
        return dict(message="Default role required, user needs least one of the following roles assigned: admin, "
                            "operator, read-only"), 400

    user = get(user_id)
    user.username = username
    user.email = email
    user.active = active
    user.profile_picture = profile_picture
    if password:
        user.password = password
    update_roles(user, roles)

    log_service.audit_log("update_user", username, f"Updating user with id {user_id}")
    return database.update(user)


def update_roles(user, roles):
    """
    Replaces the roles with new ones. This will detect
    when are roles added as well as when there are roles
    removed.

    :param user:
    :param roles:
    """
    removed_roles = []
    for ur in user.roles:
        for r in roles:
            if r.id == ur.id:
                break
        else:
            user.roles.remove(ur)
            removed_roles.append(ur.name)
            if ur.name == 'admin':
                current_app.logger.warning(f"Removing admin role for {user.username}")

    if removed_roles:
        log_service.audit_log("unassign_role", user.username, f"Un-assigning roles {removed_roles}")

    added_roles = []
    for r in roles:
        for ur in user.roles:
            if r.id == ur.id:
                break
        else:
            user.roles.append(r)
            added_roles.append(r.name)
            if r.name == 'admin':
                current_app.logger.warning(f"{user.username} added as admin")

    if added_roles:
        log_service.audit_log("assign_role", user.username, f"Assigning roles {added_roles}")


def get(user_id):
    """
    Retrieve a user from the database

    :param user_id:
    :return:
    """
    return database.get(User, user_id)


def get_by_email(email):
    """
    Retrieve a user from the database by their email address

    :param email:
    :return:
    """
    return database.get(User, email, field="email")


def get_by_username(username):
    """
    Retrieve a user from the database by their username

    :param username:
    :return:
    """
    return database.get(User, username, field="username")


def get_all():
    """
    Retrieve all users from the database.

    :return:
    """
    query = database.session_query(User)
    return database.find_all(query, User, {}).all()


def render(args):
    """
    Helper that paginates and filters data when requested
    through the REST Api

    :param args:
    :return:
    """
    query = database.session_query(User)

    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        query = database.filter(query, User, terms)

    return database.sort_and_page(query, User, args)
