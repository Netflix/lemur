"""
.. module: lemur.factory
    :platform: Unix
    :synopsis: This module contains all the needed functions to allow
    the factory app creation.

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import errno
import importlib
import os
import socket
import stat
from importlib.metadata import entry_points
from logging import Formatter, StreamHandler
from logging.handlers import RotatingFileHandler

import logmatic
import sentry_sdk
from click import get_current_context
from flask import Flask, current_app
from flask_replicated import FlaskReplicated
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

from lemur.certificates.hooks import activate_debug_dump
from lemur.common.health import mod as health
from lemur.extensions import db, migrate, principal, smtp_mail, metrics, cors

DEFAULT_BLUEPRINTS = (health,)

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
    ctx = get_current_context(silent=True)

    # get config option value from command line
    if ctx and config is None:
        script_info = ctx.obj
        if script_info:
            config = getattr(script_info, 'config')

    configure_app(app, config)
    configure_blueprints(app, blueprints)
    configure_extensions(app)
    configure_logging(app)
    configure_database(app)
    install_plugins(app)

    @app.teardown_appcontext
    def teardown(exception=None):
        if db.session:
            db.session.remove()

    @app.shell_context_processor
    def shell_context():
        return {'app': app, 'db': db}

    return app


def from_file(file_path, silent=False):
    """
    Updates the values in the config from a Python file.  This function
    behaves as if the file was imported as module with the

    :param file_path:
    :param silent:
    """

    if os.path.isfile(file_path):
        module_spec = importlib.util.spec_from_file_location("config", file_path)
        d = importlib.util.module_from_spec(module_spec)
    else:
        raise FileNotFoundError(
            f"Unable to load config file: `{file_path}`"
        )

    try:
        with open(file_path) as config_file:
            exec(  # nosec: config file safe
                compile(config_file.read(), file_path, "exec"), d.__dict__
            )
    except OSError as e:
        if silent and e.errno in (errno.ENOENT, errno.EISDIR):
            return False
        e.strerror = "Unable to load configuration file (%s)" % e.strerror
        raise
    return d


def configure_app(app, config=None):
    """
    Different ways of configuration

    :param app:
    :param config:
    :return:
    """
    # respect the config first
    if config and config != "None":
        app.config["CONFIG_PATH"] = config
        app.config.from_object(from_file(config))
    else:
        try:
            app.config.from_envvar("LEMUR_CONF")
        except RuntimeError:
            # look in default paths
            if os.path.isfile(os.path.expanduser("~/.lemur/lemur.conf.py")):
                app.config.from_object(
                    from_file(os.path.expanduser("~/.lemur/lemur.conf.py"))
                )
            else:
                app.config.from_object(
                    from_file(
                        os.path.join(
                            os.path.dirname(os.path.realpath(__file__)),
                            "default.conf.py",
                        )
                    )
                )

    # we don't use this
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


def configure_extensions(app):
    """
    Attaches and configures any needed flask extensions
    to our app.

    :param app:
    """
    db.init_app(app)
    migrate.init_app(app, db, app.config.get("FLASK_MIGRATIONS_PATH", "migrations"))
    principal.init_app(app)
    smtp_mail.init_app(app)
    metrics.init_app(app)

    # the legacy Raven[flask] relied on SENTRY_CONFIG
    if app.config.get("SENTRY_DSN", None) or app.config.get("SENTRY_CONFIG", None):
        # priority given to SENTRY_DSN
        sentry_dsn = app.config.get("SENTRY_DSN", None) or app.config["SENTRY_CONFIG"]['dsn']
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[SqlalchemyIntegration(),
                          CeleryIntegration(),
                          RedisIntegration(),
                          FlaskIntegration()],
            # associating users to errors
            send_default_pii=True,
            shutdown_timeout=60,
            environment=app.config.get("LEMUR_ENV", ''),
        )

    if app.config["CORS"]:
        # set cors defaults, if not in config
        if "CORS_ORIGINS" not in app.config:
            app.config["CORS_ORIGINS"] = "*"
        if "CORS_ALLOW_HEADERS" not in app.config:
            app.config["CORS_ALLOW_HEADERS"] = ["Authorization", "Content-Type"]

        # cors init app
        cors.init_app(
            app,
            resources=r"/api/*",
            supports_credentials=True,
        )


def configure_blueprints(app, blueprints):
    """
    We prefix our APIs with their given version so that we can support
    multiple concurrent API versions.

    :param app:
    :param blueprints:
    """
    for blueprint in blueprints:
        app.register_blueprint(blueprint, url_prefix=f"/api/{API_VERSION}")


def configure_database(app):
    if app.config.get("SQLALCHEMY_ENABLE_FLASK_REPLICATED"):
        FlaskReplicated(app)


def configure_logging(app):
    """
    Sets up application wide logging.

    :param app:
    """
    logfile = app.config.get("LOG_FILE", "lemur.log")
    # if the log file is a character special device file (ie. stdout/stderr),
    # file rotation will not work and must be disabled.
    disable_file_rotation = os.path.exists(logfile) and stat.S_ISCHR(os.stat(logfile).st_mode)
    if disable_file_rotation:
        handler = StreamHandler(open(logfile, 'a'))
    else:
        handler = RotatingFileHandler(logfile, maxBytes=10000000, backupCount=100)

    handler.setFormatter(
        Formatter(
            "%(asctime)s %(levelname)s: %(message)s " "[in %(pathname)s:%(lineno)d]"
        )
    )

    if app.config.get("LOG_JSON", False):
        handler.setFormatter(
            logmatic.JsonFormatter(extra={"hostname": socket.gethostname()})
        )

    handler.setLevel(app.config.get("LOG_LEVEL", "DEBUG"))
    app.logger.setLevel(app.config.get("LOG_LEVEL", "DEBUG"))
    app.logger.addHandler(handler)

    stream_handler = StreamHandler()
    stream_handler.setLevel(app.config.get("LOG_LEVEL", "DEBUG"))
    app.logger.addHandler(stream_handler)

    if app.config.get("DEBUG_DUMP", False):
        activate_debug_dump()


def install_plugins(app):
    """
    Installs new issuers that are not currently bundled with Lemur.

    :param app:
    :return:
    """
    from lemur.plugins import plugins
    from lemur.plugins.base import register

    for ep in entry_points().get("lemur.plugins", []):
        try:
            plugin = ep.load()
        except Exception:
            import traceback

            app.logger.error(
                "Failed to load plugin {!r}:\n{}\n".format(ep.name, traceback.format_exc())
            )
        else:
            register(plugin)

    # ensure that we have some way to notify
    with app.app_context():
        slug = app.config.get("LEMUR_DEFAULT_NOTIFICATION_PLUGIN", "email-notification")
        try:
            plugins.get(slug)
        except KeyError:
            raise Exception(
                "Unable to location notification plugin: {slug}. Ensure that "
                "LEMUR_DEFAULT_NOTIFICATION_PLUGIN is set to a valid and installed notification plugin.".format(
                    slug=slug
                )
            )

        if current_app.config.get("USER_DOMAIN_AUTHORIZATION_PROVIDER"):
            try:
                user_domain_authz_provider = plugins.get(current_app.config.get("USER_DOMAIN_AUTHORIZATION_PROVIDER"))
                user_domain_authz_provider.warmup()
            except Exception:
                import traceback

                app.logger.error(
                    "Domain authorization warmup failed, this is a best effort call:\n%s\n" % (traceback.format_exc())
                )
