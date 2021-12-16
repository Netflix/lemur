#!/usr/bin/env python
from __future__ import unicode_literals  # at top of module

import os
import sys
import base64
import requests
import json

from gunicorn.config import make_settings

from cryptography.fernet import Fernet

from flask import current_app
from flask_script import Manager, Command, Option, prompt_pass
from flask_migrate import Migrate, MigrateCommand, stamp
from flask_script.commands import ShowUrls, Clean, Server

from lemur.dns_providers.cli import manager as dns_provider_manager
from lemur.acme_providers.cli import manager as acme_manager
from lemur.sources.cli import manager as source_manager
from lemur.policies.cli import manager as policy_manager
from lemur.reporting.cli import manager as report_manager
from lemur.certificates.cli import manager as certificate_manager
from lemur.notifications.cli import manager as notification_manager
from lemur.pending_certificates.cli import manager as pending_certificate_manager

from lemur import database
from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.policies import service as policy_service
from lemur.notifications import service as notification_service

from lemur.common.utils import validate_conf

from lemur import create_app

# Needed to be imported so that SQLAlchemy create_all can find our models
from lemur.users.models import User  # noqa
from lemur.roles.models import Role  # noqa
from lemur.authorities.models import Authority  # noqa
from lemur.certificates.models import Certificate  # noqa
from lemur.destinations.models import Destination  # noqa
from lemur.domains.models import Domain  # noqa
from lemur.notifications.models import Notification  # noqa
from lemur.sources.models import Source  # noqa
from lemur.logs.models import Log  # noqa
from lemur.endpoints.models import Endpoint  # noqa
from lemur.policies.models import RotationPolicy  # noqa
from lemur.pending_certificates.models import PendingCertificate  # noqa
from lemur.dns_providers.models import DnsProvider  # noqa

from sqlalchemy.sql import text

manager = Manager(create_app)
manager.add_option("-c", "--config", dest="config_path", required=False)

migrate = Migrate(create_app)

REQUIRED_VARIABLES = [
    "LEMUR_SECURITY_TEAM_EMAIL",
    "LEMUR_DEFAULT_ORGANIZATIONAL_UNIT",
    "LEMUR_DEFAULT_ORGANIZATION",
    "LEMUR_DEFAULT_LOCATION",
    "LEMUR_DEFAULT_COUNTRY",
    "LEMUR_DEFAULT_STATE",
    "SQLALCHEMY_DATABASE_URI",
]

KEY_LENGTH = 40
DEFAULT_CONFIG_PATH = "~/.lemur/lemur.conf.py"
DEFAULT_SETTINGS = "lemur.conf.server"
SETTINGS_ENVVAR = "LEMUR_CONF"

CONFIG_TEMPLATE = """
# This is just Python which means you can inherit and tweak settings

import os
_basedir = os.path.abspath(os.path.dirname(__file__))

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
debug = False

# this is the secret key used by flask session management
SECRET_KEY = '{flask_secret_key}'

# You should consider storing these separately from your config
LEMUR_TOKEN_SECRET = '{secret_token}'
LEMUR_ENCRYPTION_KEYS = '{encryption_key}'

# this is the secret used to generate oauth state tokens
OAUTH_STATE_TOKEN_SECRET = {oauth_state_token_secret}

# List of domain regular expressions that non-admin users can issue
LEMUR_ALLOWED_DOMAINS = []

# Mail Server

LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []

# Certificate Defaults

LEMUR_DEFAULT_COUNTRY = ''
LEMUR_DEFAULT_STATE = ''
LEMUR_DEFAULT_LOCATION = ''
LEMUR_DEFAULT_ORGANIZATION = ''
LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = ''

# Authentication Providers
ACTIVE_PROVIDERS = []

# Metrics Providers
METRIC_PROVIDERS = []

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"
LOG_UPGRADE_FILE = "db_upgrade.log"


# Database

# modify this if you are not using a local database
SQLALCHEMY_DATABASE_URI = 'postgresql://lemur:lemur@localhost:5432/lemur'

# AWS

#LEMUR_INSTANCE_PROFILE = 'Lemur'

# Issuers

# These will be dependent on which 3rd party that Lemur is
# configured to use.

# VERISIGN_URL = ''
# VERISIGN_PEM_PATH = ''
# VERISIGN_FIRST_NAME = ''
# VERISIGN_LAST_NAME = ''
# VERSIGN_EMAIL = ''
"""


@MigrateCommand.command
def create():
    database.db.engine.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    database.db.create_all()
    stamp(revision="head")


@MigrateCommand.command
def drop_all():
    database.db.drop_all()


@manager.shell
def make_shell_context():
    """
    Creates a python REPL with several default imports
    in the context of the current_app

    :return:
    """
    return dict(current_app=current_app)


def generate_settings():
    """
    This command is run when ``default_path`` doesn't exist, or ``init`` is
    run and returns a string representing the default data to put into their
    settings file.
    """
    output = CONFIG_TEMPLATE.format(
        # we use Fernet.generate_key to make sure that the key length is
        # compatible with Fernet
        encryption_key=Fernet.generate_key().decode("utf-8"),
        secret_token=base64.b64encode(os.urandom(KEY_LENGTH)).decode("utf-8"),
        flask_secret_key=base64.b64encode(os.urandom(KEY_LENGTH)).decode("utf-8"),
        oauth_state_token_secret=base64.b64encode(os.urandom(KEY_LENGTH)),
    )

    return output


class InitializeApp(Command):
    """
    This command will bootstrap our database with any destinations as
    specified by our config.

    Additionally a Lemur user will be created as a default user
    and be used when certificates are discovered by Lemur.
    """

    option_list = (Option("-p", "--password", dest="password"),)

    def run(self, password):
        create()
        user = user_service.get_by_username("lemur")

        admin_role = role_service.get_by_name("admin")

        if admin_role:
            sys.stdout.write("[-] Admin role already created, skipping...!\n")
        else:
            # we create an admin role
            admin_role = role_service.create(
                "admin", description="This is the Lemur administrator role."
            )
            sys.stdout.write("[+] Created 'admin' role\n")

        operator_role = role_service.get_by_name("operator")

        if operator_role:
            sys.stdout.write("[-] Operator role already created, skipping...!\n")
        else:
            # we create an operator role
            operator_role = role_service.create(
                "operator", description="This is the Lemur operator role."
            )
            sys.stdout.write("[+] Created 'operator' role\n")

        read_only_role = role_service.get_by_name("read-only")

        if read_only_role:
            sys.stdout.write("[-] Read only role already created, skipping...!\n")
        else:
            # we create an read only role
            read_only_role = role_service.create(
                "read-only", description="This is the Lemur read only role."
            )
            sys.stdout.write("[+] Created 'read-only' role\n")

        if not user:
            if not password:
                sys.stdout.write("We need to set Lemur's password to continue!\n")
                password = prompt_pass("Password")
                password1 = prompt_pass("Confirm Password")

                if password != password1:
                    sys.stderr.write("[!] Passwords do not match!\n")
                    sys.exit(1)

            user_service.create(
                "lemur", password, "lemur@nobody.com", True, None, [admin_role]
            )
            sys.stdout.write(
                "[+] Created the user 'lemur' and granted it the 'admin' role!\n"
            )

        else:
            sys.stdout.write(
                "[-] Default user has already been created, skipping...!\n"
            )

        intervals = current_app.config.get(
            "LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS", []
        )
        sys.stdout.write(
            "[!] Creating {num} notifications for {intervals} days as specified by LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS\n".format(
                num=len(intervals), intervals=",".join([str(x) for x in intervals])
            )
        )

        recipients = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")
        sys.stdout.write("[+] Creating expiration email notifications!\n")
        sys.stdout.write(
            "[!] Using {0} as specified by LEMUR_SECURITY_TEAM_EMAIL for notifications\n".format(
                recipients
            )
        )
        notification_service.create_default_expiration_notifications(
            "DEFAULT_SECURITY", recipients=recipients
        )

        _DEFAULT_ROTATION_INTERVAL = "default"
        default_rotation_interval = policy_service.get_by_name(
            _DEFAULT_ROTATION_INTERVAL
        )

        if default_rotation_interval:
            sys.stdout.write(
                "[-] Default rotation interval policy already created, skipping...!\n"
            )
        else:
            days = current_app.config.get("LEMUR_DEFAULT_ROTATION_INTERVAL", 30)
            sys.stdout.write(
                "[+] Creating default certificate rotation policy of {days} days before issuance.\n".format(
                    days=days
                )
            )
            policy_service.create(days=days, name=_DEFAULT_ROTATION_INTERVAL)

        sys.stdout.write("[/] Done!\n")


class CreateUser(Command):
    """
    This command allows for the creation of a new user within Lemur.
    """

    option_list = (
        Option("-u", "--username", dest="username", required=True),
        Option("-e", "--email", dest="email", required=True),
        Option("-a", "--active", dest="active", default=True),
        Option("-r", "--roles", dest="roles", action="append", default=[]),
        Option("-p", "--password", dest="password", default=None),
    )

    def run(self, username, email, active, roles, password):
        role_objs = []
        for r in roles:
            role_obj = role_service.get_by_name(r)
            if role_obj:
                role_objs.append(role_obj)
            else:
                sys.stderr.write("[!] Cannot find role {0}\n".format(r))
                sys.exit(1)

        if not password:
            password1 = prompt_pass("Password")
            password2 = prompt_pass("Confirm Password")
            password = password1

            if password1 != password2:
                sys.stderr.write("[!] Passwords do not match!\n")
                sys.exit(1)

        user_service.create(username, password, email, active, None, role_objs)
        sys.stdout.write("[+] Created new user: {0}\n".format(username))


class ResetPassword(Command):
    """
    This command allows you to reset a user's password.
    """

    option_list = (Option("-u", "--username", dest="username", required=True),)

    def run(self, username):
        user = user_service.get_by_username(username)

        if not user:
            sys.stderr.write("[!] No user found for username: {0}\n".format(username))
            sys.exit(1)

        sys.stderr.write("[+] Resetting password for {0}\n".format(username))
        password1 = prompt_pass("Password")
        password2 = prompt_pass("Confirm Password")

        if password1 != password2:
            sys.stderr.write("[!] Passwords do not match\n")
            sys.exit(1)

        user.password = password1
        user.hash_password()
        database.commit()


class CreateRole(Command):
    """
    This command allows for the creation of a new role within Lemur
    """

    option_list = (
        Option("-n", "--name", dest="name", required=True),
        Option("-u", "--users", dest="users", default=[]),
        Option("-d", "--description", dest="description", required=True),
    )

    def run(self, name, users, description):
        user_objs = []
        for u in users:
            user_obj = user_service.get_by_username(u)
            if user_obj:
                user_objs.append(user_obj)
            else:
                sys.stderr.write("[!] Cannot find user {0}".format(u))
                sys.exit(1)
        role_service.create(name, description=description, users=users)
        sys.stdout.write("[+] Created new role: {0}".format(name))


class LemurServer(Command):
    """
    This is the main Lemur server, it runs the flask app with gunicorn and
    uses any configuration options passed to it.


    You can pass all standard gunicorn flags to this command as if you were
    running gunicorn itself.

    For example:

    lemur start -w 4 -b 127.0.0.0:8002

    Will start gunicorn with 4 workers bound to 127.0.0.0:8002
    """

    description = "Run the app within Gunicorn"

    def get_options(self):
        settings = make_settings()
        options = []
        for setting, klass in settings.items():
            if klass.cli:
                if klass.action:
                    if klass.action == "store_const":
                        options.append(
                            Option(*klass.cli, const=klass.const, action=klass.action)
                        )
                    else:
                        options.append(Option(*klass.cli, action=klass.action))
                else:
                    options.append(Option(*klass.cli))

        return options

    def run(self, *args, **kwargs):
        from gunicorn.app.wsgiapp import WSGIApplication

        app = WSGIApplication()

        # run startup tasks on an app like object
        validate_conf(current_app, REQUIRED_VARIABLES)

        app.app_uri = 'lemur:create_app(config_path="{0}")'.format(
            current_app.config.get("CONFIG_PATH")
        )

        return app.run()


@manager.command
def create_config(config_path=None):
    """
    Creates a new configuration file if one does not already exist
    """
    if not config_path:
        config_path = DEFAULT_CONFIG_PATH

    config_path = os.path.expanduser(config_path)
    dir = os.path.dirname(config_path)

    if not os.path.exists(dir):
        os.makedirs(dir)

    config = generate_settings()
    with open(config_path, "w") as f:
        f.write(config)

    sys.stdout.write("[+] Created a new configuration file {0}\n".format(config_path))


@manager.command
def lock(path=None):
    """
    Encrypts a given path. This directory can be used to store secrets needed for normal
    Lemur operation. This is especially useful for storing secrets needed for communication
    with third parties (e.g. external certificate authorities).

    Lemur does not assume anything about the contents of the directory and will attempt to
    encrypt all files contained within. Currently this has only been tested against plain
    text files.

    Path defaults ~/.lemur/keys

    :param: path
    """
    if not path:
        path = os.path.expanduser("~/.lemur/keys")

    dest_dir = os.path.join(path, "encrypted")
    sys.stdout.write("[!] Generating a new key...\n")

    key = Fernet.generate_key()

    if not os.path.exists(dest_dir):
        sys.stdout.write("[+] Creating encryption directory: {0}\n".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(os.path.join(path, "decrypted")):
        for f in files:
            source = os.path.join(root, f)
            dest = os.path.join(dest_dir, f + ".enc")
            with open(source, "rb") as in_file, open(dest, "wb") as out_file:
                f = Fernet(key)
                data = f.encrypt(in_file.read())
                out_file.write(data)
                sys.stdout.write(
                    "[+] Writing file: {0} Source: {1}\n".format(dest, source)
                )

    sys.stdout.write("[+] Keys have been encrypted with key {0}\n".format(key))


@manager.command
def unlock(path=None):
    """
    Decrypts all of the files in a given directory with provided password.
    This is most commonly used during the startup sequence of Lemur
    allowing it to go from source code to something that can communicate
    with external services.

    Path defaults ~/.lemur/keys

    :param: path
    """
    key = prompt_pass("[!] Please enter the encryption password")

    if not path:
        path = os.path.expanduser("~/.lemur/keys")

    dest_dir = os.path.join(path, "decrypted")
    source_dir = os.path.join(path, "encrypted")

    if not os.path.exists(dest_dir):
        sys.stdout.write("[+] Creating decryption directory: {0}\n".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            source = os.path.join(source_dir, f)
            dest = os.path.join(dest_dir, ".".join(f.split(".")[:-1]))
            with open(source, "rb") as in_file, open(dest, "wb") as out_file:
                f = Fernet(key)
                data = f.decrypt(in_file.read())
                out_file.write(data)
                sys.stdout.write(
                    "[+] Writing file: {0} Source: {1}\n".format(dest, source)
                )

    sys.stdout.write("[+] Keys have been unencrypted!\n")


@manager.command
def publish_verisign_units():
    """
    Simple function that queries verisign for API units and posts the mertics to
    Atlas API for other teams to consume.
    :return:
    """
    from lemur.plugins import plugins

    v = plugins.get("verisign-issuer")
    units = v.get_available_units()

    metrics = {}
    for item in units:
        if item["@type"] in metrics.keys():
            metrics[item["@type"]] += int(item["@remaining"])
        else:
            metrics.update({item["@type"]: int(item["@remaining"])})

    for name, value in metrics.items():
        metric = [
            {
                "timestamp": 1321351651,
                "type": "GAUGE",
                "name": "Symantec {0} Unit Count".format(name),
                "tags": {},
                "value": value,
            }
        ]

        requests.post("http://localhost:8078/metrics", data=json.dumps(metric))


def main():
    manager.add_command("start", LemurServer())
    manager.add_command("runserver", Server(host="127.0.0.1", threaded=True))
    manager.add_command("clean", Clean())
    manager.add_command("show_urls", ShowUrls())
    manager.add_command("db", MigrateCommand)
    manager.add_command("init", InitializeApp())
    manager.add_command("create_user", CreateUser())
    manager.add_command("reset_password", ResetPassword())
    manager.add_command("create_role", CreateRole())
    manager.add_command("source", source_manager)
    manager.add_command("certificate", certificate_manager)
    manager.add_command("notify", notification_manager)
    manager.add_command("report", report_manager)
    manager.add_command("policy", policy_manager)
    manager.add_command("pending_certs", pending_certificate_manager)
    manager.add_command("dns_providers", dns_provider_manager)
    manager.add_command("acme", acme_manager)
    manager.run()


if __name__ == "__main__":
    main()
