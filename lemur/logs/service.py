"""
.. module: lemur.logs.service
    :platform: Unix
    :synopsis: This module contains all of the services level functions used to
    administer logs in Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from lemur import database
from lemur.logs.models import Log


def create(user, type, certificate=None):
    """
    Creates logs a given action.

    :param user:
    :param type:
    :param certificate:
    :return:
    """
    current_app.logger.info("[lemur-audit] action: {0}, user: {1}, certificate: {2}.".format(type, user.email, certificate.name))
    view = Log(user_id=user.id, log_type=type, certificate_id=certificate.id)
    database.add(view)
    database.commit()


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

    filt = args.pop('filter')

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Log, terms)

    return database.sort_and_page(query, Log, args)
