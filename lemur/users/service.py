"""
.. module: lemur.users.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer users in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.users.models import User


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
    user = User(
        password=password,
        username=username,
        email=email,
        active=active,
        profile_picture=profile_picture,
    )
    user.roles = roles
    return database.create(user)


def update(user_id, username, email, active, profile_picture, roles):
    """
    Updates an existing user

    :param user_id:
    :param username:
    :param email:
    :param active:
    :param profile_picture:
    :param roles:
    :return:
    """
    user = get(user_id)
    user.username = username
    user.email = email
    user.active = active
    user.profile_picture = profile_picture
    update_roles(user, roles)
    return database.update(user)


def update_roles(user, roles):
    """
    Replaces the roles with new ones. This will detect
    when are roles added as well as when there are roles
    removed.

    :param user:
    :param roles:
    """
    for ur in user.roles:
        for r in roles:
            if r.id == ur.id:
                break
        else:
            user.roles.remove(ur)

    for r in roles:
        for ur in user.roles:
            if r.id == ur.id:
                break
        else:
            user.roles.append(r)


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
