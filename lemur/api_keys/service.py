"""
.. module: lemur.api_keys.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
from lemur import database
from lemur.api_keys.models import ApiKey
from lemur.logs import service as log_service


def get(aid):
    """
    Retrieves an api key by its ID.
    :param aid: The access key id to get.
    :return:
    """
    return database.get(ApiKey, aid)


def delete(access_key):
    """
    Delete an access key. This is one way to remove a key, though you probably should just set revoked.
    :param access_key:
    :return:
    """
    log_service.audit_log("delete_api_key", access_key.name, "Deleting the API key")
    database.delete(access_key)


def revoke(aid):
    """
    Revokes an api key.
    :param aid:
    :return:
    """
    api_key = get(aid)
    setattr(api_key, "revoked", True)

    log_service.audit_log("revoke_api_key", api_key.name, "Revoking API key")
    return database.update(api_key)


def get_all_api_keys():
    """
    Retrieves all Api Keys.
    :return:
    """
    return ApiKey.query.all()


def create(**kwargs):
    """
    Creates a new API Key.

    :param kwargs:
    :return:
    """
    api_key = ApiKey(**kwargs)
    # this logs only metadata about the api key
    log_service.audit_log("create_api_key", api_key.name, f"Creating the API key {api_key}")

    database.create(api_key)
    return api_key


def update(api_key, **kwargs):
    """
    Updates an api key.
    :param api_key:
    :param kwargs:
    :return:
    """
    for key, value in kwargs.items():
        setattr(api_key, key, value)

    log_service.audit_log("update_api_key", api_key.name, f"Update summary - {kwargs}")
    return database.update(api_key)


def render(args):
    """
    Helper to parse REST Api requests

    :param args:
    :return:
    """
    query = database.session_query(ApiKey)
    user_id = args.pop("user_id", None)
    aid = args.pop("id", None)
    has_permission = args.pop("has_permission", False)
    requesting_user_id = args.pop("requesting_user_id")

    if user_id:
        query = query.filter(ApiKey.user_id == user_id)

    if aid:
        query = query.filter(ApiKey.id == aid)

    if not has_permission:
        query = query.filter(ApiKey.user_id == requesting_user_id)

    return database.sort_and_page(query, ApiKey, args)
