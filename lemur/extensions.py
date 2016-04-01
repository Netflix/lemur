"""
.. module: lemur.extensions
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask.ext.sqlalchemy import SQLAlchemy
db = SQLAlchemy()

from flask.ext.migrate import Migrate
migrate = Migrate()

from flask.ext.bcrypt import Bcrypt
bcrypt = Bcrypt()

from flask.ext.principal import Principal
principal = Principal()

from flask_mail import Mail
smtp_mail = Mail()

from lemur.metrics import Metrics
metrics = Metrics()
