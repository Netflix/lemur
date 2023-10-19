"""
.. module: lemur.logs.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer logs in Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app, g

from lemur import database
from lemur.logs.models import Log
from lemur.users.models import User
from lemur.certificates.models import Certificate


def create(user, type, certificate=None):
    """
    Creates logs a given action.

    :param user:
    :param type:
    :param certificate:
    :return:
    """
    log_data = {
        "function": "lemur-audit",
        "action": type,
        "user": user.email,
        "certificate": certificate.name,
        "message": f"[lemur-audit] action: {type}, user: {user.email}, certificate: {certificate.name}."
    }
    # format before August 2021: f"[lemur-audit] action: {type}, user: {user.email}, certificate: {certificate.name}."
    current_app.logger.info(log_data)

    view = Log(user_id=user.id, log_type=type, certificate_id=certificate.id)
    database.add(view)
    database.commit()


def audit_log(action, entity, message):
    """
    Logs given action
    :param action: The action being logged e.g. assign_role, create_role etc
    :param entity: The entity undergoing the action e.g. name of the role
    :param message: Additional info e.g. Role being assigned to user X
    :return:
    """

    user = g.current_user.email if hasattr(g, 'current_user') else "LEMUR"
    log_data = {
        "function": "lemur-audit",
        "action": action,
        "user": user,
        "entity": entity,
        "details": message,
        "message": f"[lemur-audit] action: {action}, user: {user}, entity: {entity}, details: {message}."
    }
    # format before August 2021: f"[lemur-audit] action: {action}, user: {user}, entity: {entity}, details: {message}"
    current_app.logger.info(log_data)


def get_all():
    """
    Retrieve all logs from the database.

    :return:
    """
    query = database.session_query(Log)
    return database.find_all(query, Log, {}).all()


def render(args):
    """
    Helper that paginates and filters data when requested
    through the REST Api

    :param args:
    :return:
    """
    query = database.session_query(Log)

    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")

        if "certificate.name" in terms:
            sub_query = database.session_query(Certificate.id).filter(
                Certificate.name.ilike(f"%{terms[1]}%")
            )

            query = query.filter(Log.certificate_id.in_(sub_query))

        elif "user.email" in terms:
            sub_query = database.session_query(User.id).filter(
                User.email.ilike(f"%{terms[1]}%")
            )

            query = query.filter(Log.user_id.in_(sub_query))

        else:
            query = database.filter(query, Log, terms)

    return database.sort_and_page(query, Log, args)
