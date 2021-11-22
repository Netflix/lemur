"""
.. module: lemur.common.health
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from sentry_sdk import capture_exception

from lemur.database import db


mod = Blueprint("healthCheck", __name__)


@mod.route("/healthcheck")
def health():
    try:
        if healthcheck(db):
            return "ok"
    except Exception:
        capture_exception()
        return "db check failed"


def healthcheck(db):
    with db.engine.connect() as connection:
        connection.execute("SELECT 1;")
    return True
