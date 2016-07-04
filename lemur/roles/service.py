"""
.. module: service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer roles in Lemur

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.roles.models import Role
from lemur.users.models import User


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
    role.name = name
    role.description = description
    if users:
        role.users = users
    database.update(role)
    return role


def create(name, password=None, description=None, username=None, users=None):
    """
    Create a new role

    :param name:
    :param users:
    :param description:
    :param username:
    :param password:
    :return:
    """
    role = Role(name=name, description=description, username=username, password=password)
    if users:
        role.users = users
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
    Retrieve a role by it's name

    :param role_name:
    :return:
    """
    return database.get(Role, role_name, field='name')


def delete(role_id):
    """
    Remove a role

    :param role_id:
    :return:
    """
    return database.delete(get(role_id))


def render(args):
    """
    Helper that filters subsets of roles depending on the parameters
    passed to the REST Api

    :param args:
    :return:
    """
    query = database.session_query(Role)
    filt = args.pop('filter')
    user_id = args.pop('user_id', None)
    authority_id = args.pop('authority_id', None)

    if user_id:
        query = query.filter(Role.users.any(User.id == user_id))

    if authority_id:
        query = query.filter(Role.authority_id == authority_id)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Role, terms)

    return database.sort_and_page(query, Role, args)
