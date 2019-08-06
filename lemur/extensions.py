"""
.. module: lemur.extensions
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask_sqlalchemy import SQLAlchemy as SA
from sqlalchemy_searchable import make_searchable


class SQLAlchemy(SA):
    def apply_pool_defaults(self, app, options):
        SA.apply_pool_defaults(self, app, options)
        options["pool_pre_ping"] = True


db = SQLAlchemy()
make_searchable(db.metadata)

from flask_migrate import Migrate

migrate = Migrate()

from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

from flask_principal import Principal

principal = Principal(use_sessions=False)

from flask_mail import Mail

smtp_mail = Mail()

from lemur.metrics import Metrics

metrics = Metrics()

from raven.contrib.flask import Sentry

sentry = Sentry()

from blinker import Namespace

signals = Namespace()

from flask_cors import CORS

cors = CORS()
