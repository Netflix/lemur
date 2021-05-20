"""
.. module: lemur.extensions
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy


class SQLAlchemy(_BaseSQLAlchemy):
    def apply_pool_defaults(self, app, options):
        """
        Set default engine options. We enable `pool_pre_ping` to be the default value.
        """
        options = super().apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
        return options


db = SQLAlchemy()

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

from blinker import Namespace

signals = Namespace()

from flask_cors import CORS

cors = CORS()
