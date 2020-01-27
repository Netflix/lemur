"""
.. module: lemur.common.health
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import Blueprint
from lemur.database import db
from lemur.extensions import sentry

mod = Blueprint("healthCheck", __name__)


@mod.route("/healthcheck")
def health():
    try:
        if healthcheck(db):
            return "ok"
    except Exception:
        sentry.captureException()
        return "db check failed"


def healthcheck(db):
    with db.engine.connect() as connection:
        connection.execute("SELECT 1;")
    return True
