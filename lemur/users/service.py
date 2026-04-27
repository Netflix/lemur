"""
.. module: lemur.users.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer users in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from datetime import datetime

import arrow
from flask import current_app

from lemur import database
from lemur.logs import service as log_service
from lemur.users.models import User, TemporaryBreakGlassGrant

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
            if ur.name == "admin":
                current_app.logger.warning(f"Removing admin role for {user.username}")

    if removed_roles:
        log_service.audit_log(
            "unassign_role", user.username, f"Un-assigning roles {removed_roles}"
        )

    added_roles = []
    for r in roles:
        for ur in user.roles:
            if r.id == ur.id:
                break
        else:
            user.roles.append(r)
            added_roles.append(r.name)
            if r.name == "admin":
                current_app.logger.warning(f"{user.username} added as admin")

    if added_roles:
        log_service.audit_log(
            "assign_role", user.username, f"Assigning roles {added_roles}"
        )


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


# --- Temporary break-glass grants (admin grants break-glass role to a user temporarily) ---

BREAK_GLASS_ROLE_NAME = "break-glass"


def get_effective_role_names(user):
    """
    Returns the list of role names for the user, including 'break-glass' if they
    have an active (non-expired) temporary break-glass grant.

    :param user: User instance
    :return: list of role name strings
    """
    if not user:
        return []
    role_names = [r.name for r in user.roles]
    if has_active_break_glass_grant(user.id):
        if BREAK_GLASS_ROLE_NAME not in role_names:
            role_names.append(BREAK_GLASS_ROLE_NAME)
    return role_names


def has_active_break_glass_grant(user_id):
    """
    Returns True if the user has a non-expired temporary break-glass grant.

    :param user_id: user id
    :return: bool
    """
    now = arrow.utcnow()
    q = (
        database.session_query(TemporaryBreakGlassGrant)
        .filter(TemporaryBreakGlassGrant.user_id == user_id)
        .filter(TemporaryBreakGlassGrant.expires_at > now)
    )
    return q.first() is not None


def get_active_break_glass_grant(user_id):
    """
    Returns the active temporary break-glass grant for the user, or None.

    :param user_id: user id
    :return: TemporaryBreakGlassGrant or None
    """
    now = arrow.utcnow()
    q = (
        database.session_query(TemporaryBreakGlassGrant)
        .filter(TemporaryBreakGlassGrant.user_id == user_id)
        .filter(TemporaryBreakGlassGrant.expires_at > now)
    )
    return q.first()


def grant_break_glass(user_id, granted_by_id, expires_at):
    """
    Grant the break-glass role to a user until expires_at. Only admins should call this.
    If the user already has an active grant, it is replaced (single active grant per user).

    :param user_id: id of user to grant break-glass to
    :param granted_by_id: id of admin granting
    :param expires_at: arrow or datetime when the grant expires
    :return: TemporaryBreakGlassGrant
    """
    if hasattr(expires_at, "datetime"):
        expires_at = expires_at.datetime
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = arrow.get(expires_at).replace(tzinfo="UTC").datetime
    revoke_break_glass(user_id)
    grant = TemporaryBreakGlassGrant(
        user_id=user_id,
        granted_by_id=granted_by_id,
        expires_at=expires_at,
    )
    database.create(grant)
    user = get(user_id)
    log_service.audit_log(
        "grant_break_glass",
        user.username if user else str(user_id),
        f"Temporary break-glass granted until {expires_at} by user id {granted_by_id}",
    )
    return grant


def revoke_break_glass(user_id):
    """
    Remove any active temporary break-glass grant for the user.

    :param user_id: user id
    :return: number of grants removed
    """
    now = arrow.utcnow()
    q = (
        database.session_query(TemporaryBreakGlassGrant)
        .filter(TemporaryBreakGlassGrant.user_id == user_id)
        .filter(TemporaryBreakGlassGrant.expires_at > now)
    )
    grants = q.all()
    for grant in grants:
        database.delete(grant)
    if grants:
        user = get(user_id)
        log_service.audit_log(
            "revoke_break_glass",
            user.username if user else str(user_id),
            "Temporary break-glass revoked",
        )
    return len(grants)
