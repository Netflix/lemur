"""
.. module: lemur.policies.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur import database
from lemur.policies.models import RotationPolicy
from sqlalchemy import cast, Integer


def get(policy_id):
    """
    Retrieves policy by its ID.
    :param policy_id:
    :return:
    """
    return database.get(RotationPolicy, policy_id)


def get_by_name(policy_name):
    """
    Retrieves policy by its name.
    :param policy_name:
    :return:
    """
    return database.get_all(RotationPolicy, policy_name, field="name").all()


def delete(policy_id):
    """
    Delete a rotation policy.
    :param policy_id:
    :return:
    """
    database.delete(get(policy_id))


def get_all_policies():
    """
    Retrieves all rotation policies.
    :return:
    """
    return RotationPolicy.query.all()


def create(**kwargs):
    """
    Creates a new rotation policy.
    :param kwargs:
    :return:
    """
    policy = RotationPolicy(**kwargs)
    database.create(policy)
    return policy


def update(policy_id, **kwargs):
    """
    Updates a policy.
    :param policy_id:
    :param kwargs:
    :return:
    """
    policy = get(policy_id)

    for key, value in kwargs.items():
        setattr(policy, key, value)

    return database.update(policy)


def render(args):
    """
    Helper to parse REST Api requests
    :param args:
    :return:
    """
    query = database.session_query(RotationPolicy)
    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")
        term = "%{0}%".format(terms[1])
        print('123!!!',terms, term)
        if "name" in terms:
            query = query.filter(RotationPolicy.name.ilike(term))

        if "days" in terms:
            if terms[1] == 'null':
                pass
            else:
                query = query.filter(RotationPolicy.days == cast(terms[1], Integer))

    return database.sort_and_page(query, RotationPolicy, args)