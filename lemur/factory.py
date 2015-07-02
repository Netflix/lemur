"""
.. module: lemur.factory
    :platform: Unix
    :synopsis: This module contains all the needed functions to allow
    the factory app creation.

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import os
import imp
import errno

from logging import Formatter
from logging.handlers import RotatingFileHandler

from flask import Flask
from lemur.common.health import mod as health
from lemur.exceptions import NoEncryptionKeyFound
from lemur.extensions import db, migrate, principal


DEFAULT_BLUEPRINTS = (
    health,
)

API_VERSION = 1


def create_app(app_name=None, blueprints=None, config=None):
    """
    Lemur application factory

    :param config:
    :param app_name:
    :param blueprints:
    :return:
    """
    if not blueprints:
        blueprints = DEFAULT_BLUEPRINTS
    else:
        blueprints = blueprints + DEFAULT_BLUEPRINTS

    if not app_name:
        app_name = __name__

    app = Flask(app_name)
    configure_app(app, config)
    configure_blueprints(app, blueprints)
    configure_extensions(app)
    configure_logging(app)

    @app.teardown_appcontext
    def teardown(exception=None):
        if db.session:
            db.session.remove()

    return app


def from_file(file_path, silent=False):
    """
    Updates the values in the config from a Python file.  This function
    behaves as if the file was imported as module with the

    :param file_path:
    :param silent:
    """
    d = imp.new_module('config')
    d.__file__ = file_path
    try:
        with open(file_path) as config_file:
            exec(compile(config_file.read(), file_path, 'exec'), d.__dict__)
    except IOError as e:
        if silent and e.errno in (errno.ENOENT, errno.EISDIR):
            return False
        e.strerror = 'Unable to load configuration file (%s)' % e.strerror
        raise
    return d


def configure_app(app, config=None):
    """
    Different ways of configuration

    :param app:
    :param config:
    :return:
    """
    try:
        app.config.from_envvar("LEMUR_CONF")
    except RuntimeError:
        if config and config != 'None':
            app.config.from_object(from_file(config))
        elif os.path.isfile(os.path.expanduser("~/.lemur/lemur.conf.py")):
            app.config.from_object(from_file(os.path.expanduser("~/.lemur/lemur.conf.py")))
        else:
            app.config.from_object(from_file(os.path.join(os.getcwd(), 'default.conf.py')))



def configure_extensions(app):
    """
    Attaches and configures any needed flask extensions
    to our app.

    :param app:
    """
    db.init_app(app)
    migrate.init_app(app, db)
    principal.init_app(app)


def configure_blueprints(app, blueprints):
    """
    We prefix our APIs with their given version so that we can support
    multiple concurrent API versions.

    :param app:
    :param blueprints:
    """
    for blueprint in blueprints:
        app.register_blueprint(blueprint, url_prefix="/api/{0}".format(API_VERSION))


def configure_logging(app):
    """
    Sets up application wide logging.

    :param app:
    """
    handler = RotatingFileHandler(app.config.get('LOG_FILE', 'lemur.log'), maxBytes=10000000, backupCount=100)

    handler.setFormatter(Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))

    handler.setLevel(app.config.get('LOG_LEVEL', 'DEBUG'))
    app.logger.setLevel(app.config.get('LOG_LEVEL', 'DEBUG'))
    app.logger.addHandler(handler)

