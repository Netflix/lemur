#!/usr/bin/env python

import click
import os
import sys
import base64
import requests
import json

from cryptography.fernet import Fernet

from flask import current_app
from flask.cli import FlaskGroup, pass_script_info
from flask_migrate.cli import db
from flask_migrate import stamp

from lemur.dns_providers.cli import cli as dns_provider_cli
from lemur.acme_providers.cli import cli as acme_cli
from lemur.sources.cli import cli as source_cli
from lemur.policies.cli import cli as policy_cli
from lemur.reporting.cli import cli as report_cli
from lemur.certificates.cli import cli as certificate_cli
from lemur.notifications.cli import cli as notification_cli
from lemur.pending_certificates.cli import cli as pending_certificate_cli


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


@click.group(cls=FlaskGroup, create_app=create_app)
@click.option('-c', '--config', help="Path to default configuration file for Lemur.")
@pass_script_info
def cli(script_info, config):
    script_info.config = config


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
DEBUG = False

# this is the secret key used by flask session management
SECRET_KEY = "{flask_secret_key}"

# You should consider storing these separately from your config
LEMUR_TOKEN_SECRET = "{secret_token}"
LEMUR_TOKEN_SECRETS = [LEMUR_TOKEN_SECRET]
LEMUR_ENCRYPTION_KEYS = "{encryption_key}"

# this is the secret used to generate oauth state tokens
OAUTH_STATE_TOKEN_SECRET = {oauth_state_token_secret}

# List of domain regular expressions that non-admin users can issue
LEMUR_ALLOWED_DOMAINS = []

# Mail Server

LEMUR_EMAIL = ""
LEMUR_SECURITY_TEAM_EMAIL = []

# Certificate Defaults

LEMUR_DEFAULT_COUNTRY = ""
LEMUR_DEFAULT_STATE = ""
LEMUR_DEFAULT_LOCATION = ""
LEMUR_DEFAULT_ORGANIZATION = ""
LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = ""

# Authentication Providers
ACTIVE_PROVIDERS = []

# Metrics Providers
METRIC_PROVIDERS = []

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"
LOG_UPGRADE_FILE = "db_upgrade.log"
LOG_REQUEST_HEADERS = False
LOG_SANITIZE_REQUEST_HEADERS = True
LOG_REQUEST_HEADERS_SKIP_ENDPOINT = ["/metrics", "/healthcheck"]  # These endpoints are noisy so skip them by default

# Database

# modify this if you are not using a local database
SQLALCHEMY_DATABASE_URI = "postgresql://lemur:lemur@localhost:5432/lemur"

# AWS

#LEMUR_INSTANCE_PROFILE = "Lemur"

# Issuers

# These will be dependent on which 3rd party that Lemur is
# configured to use.

# VERISIGN_URL = ""
# VERISIGN_PEM_PATH = ""
# VERISIGN_FIRST_NAME = ""
# VERISIGN_LAST_NAME = ""
# VERSIGN_EMAIL = ""

# Set of controls to use around ingesting user group information from the IDP
# Allows mapping user groups to Lemur roles and automatically creating them
IDP_GROUPS_KEYS = ["googleGroups"]  # a list of keys used by IDP(s) to return user groups (profile[IDP_GROUPS_KEY])
# Note that prefix/suffix can be commented out or set to "" if no filtering against naming convention is desired
# IDP_ROLES_PREFIX = "PREFIX-"  # prefix for all IDP-defined roles, used to match naming conventions
# IDP_ROLES_SUFFIX = "_SUFFIX"  # suffix for all IDP-defined roles, used to match naming conventions
# IDP_ROLES_DESCRIPTION = "Automatically generated role"  # Description to attach to automatically generated roles
# IDP_ROLES_MAPPING = {{}}  # Dictionary that matches the IDP group name to the Lemur role. The Lemur role must exist.
# Example: IDP_ROLES_MAPPING = {{"security": "admin", "engineering": "operator", "jane_from_accounting": "read-only"}}
IDP_ASSIGN_ROLES_FROM_USER_GROUPS = True  # Assigns a Lemur role for each group found attached to the user
IDP_CREATE_ROLES_FROM_USER_GROUPS = True  # Creates a Lemur role for each group found attached to the user if missing
# Protects the built-in groups and prevents dynamically assigning users to them. Prevents IDP admin from becoming
# Lemur admin. Use IDP_ROLES_MAPPING to create a mapping to assign these groups if desired. eg {{"admin": "admin"}}
IDP_PROTECT_BUILTINS = True
IDP_CREATE_PER_USER_ROLE = True  # Generates Lemur role for each user (allows cert assignment to a single user)

"""


def create_all():
    database.db.engine.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    database.db.create_all()
    stamp(revision="head")


@db.command("create", help="Create all lemur database tables")
def create():
    create_all()


@db.command("drop_all", help="Drop all lemur database tables")
def drop_all():
    database.db.drop_all()


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


@cli.command("init")
@click.option("-p", "--password", "password")
def initialize_app(password):
    """
    This command will bootstrap our database with any destinations as
    specified by our config.

    Additionally a Lemur user will be created as a default user
    and be used when certificates are discovered by Lemur.
    """
    create_all()
    user = user_service.get_by_username("lemur")

    admin_role = role_service.get_by_name("admin")

    if admin_role:
        click.echo("[-] Admin role already created, skipping...!")
    else:
        # we create an admin role
        admin_role = role_service.create(
            "admin", description="This is the Lemur administrator role."
        )
        click.echo("[+] Created 'admin' role")

    operator_role = role_service.get_by_name("operator")

    if operator_role:
        click.echo("[-] Operator role already created, skipping...!")
    else:
        # we create an operator role
        operator_role = role_service.create(
            "operator", description="This is the Lemur operator role."
        )
        click.echo("[+] Created 'operator' role")

    global_cert_issuer_role = role_service.get_by_name("global_cert_issuer")

    if global_cert_issuer_role:
        click.echo("[-] global_cert_issuer role already created, skipping...!")
    else:
        # we create a global_cert_issuer role
        global_cert_issuer_role = role_service.create(
            "global_cert_issuer", description="This is the Lemur global_cert_issuer role."
        )
        click.echo("[+] Created 'global_cert_issuer' role")

    read_only_role = role_service.get_by_name("read-only")

    if read_only_role:
        click.echo("[-] Read only role already created, skipping...!")
    else:
        # we create an read only role
        read_only_role = role_service.create(
            "read-only", description="This is the Lemur read only role."
        )
        click.echo("[+] Created 'read-only' role")

    if not user:
        if not password:
            click.echo("We need to set Lemur's password to continue!")
            password = click.prompt("Password", hide_input=True)
            password1 = click.prompt("Confirm Password", hide_input=True)

            if password != password1:
                click.echo("[!] Passwords do not match!")
                sys.exit(1)

        user_service.create(
            "lemur", password, "lemur@nobody.com", True, None, [admin_role]
        )
        click.echo(
            "[+] Created the user 'lemur' and granted it the 'admin' role!\n"
        )

    else:
        click.echo(
            "[-] Default user has already been created, skipping...!\n"
        )

    intervals = current_app.config.get(
        "LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS", []
    )
    click.echo(
        "[!] Creating {num} notifications for {intervals} days as specified by LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS".format(
            num=len(intervals), intervals=",".join([str(x) for x in intervals])
        )
    )

    recipients = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")
    click.echo("[+] Creating expiration email notifications!")
    click.echo(
        "[!] Using {} as specified by LEMUR_SECURITY_TEAM_EMAIL for notifications".format(
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
        click.echo(
            "[-] Default rotation interval policy already created, skipping...!\n"
        )
    else:
        days = current_app.config.get("LEMUR_DEFAULT_ROTATION_INTERVAL", 30)
        click.echo(
            "[+] Creating default certificate rotation policy of {days} days before issuance.".format(
                days=days
            )
        )
        policy_service.create(days=days, name=_DEFAULT_ROTATION_INTERVAL)

    click.echo("[/] Done!")


@cli.command("create_user")
@click.option("-u", "--username", "username", required=True)
@click.option("-e", "--email", "email", required=True)
@click.option("-a", "--active", "active", type=bool, default=True, show_default=True)
@click.option("-r", "--roles", "roles", multiple=True, required=True)
@click.option("-p", "--password", "password")
def create_user(username, email, active, roles, password):
    """
    This command allows for the creation of a new user within Lemur.
    """
    role_objs = []
    for r in roles:
        role_obj = role_service.get_by_name(r)
        if role_obj:
            role_objs.append(role_obj)
        else:
            click.echo(f"[!] Cannot find role {r}")
            sys.exit(1)

    if not password:
        password1 = click.prompt("Password", hide_input=True)
        password2 = click.prompt("Confirm Password", hide_input=True)
        password = password1

        if password1 != password2:
            click.echo("[!] Passwords do not match!")
            sys.exit(1)

    user_service.create(username, password, email, active, None, role_objs)
    click.echo(f"[+] Created new user: {username}")


@cli.command("reset_password")
@click.option("-u", "--username", "username", required=True)
def reset_password(username):
    """
    This command allows you to reset a user's password.
    """
    user = user_service.get_by_username(username)

    if not user:
        click.echo(f"[!] No user found for username: {username}")
        sys.exit(1)

    click.echo(f"[+] Resetting password for {username}")
    password1 = click.prompt("Password", hide_input=True)
    password2 = click.prompt("Confirm Password", hide_input=True)

    if password1 != password2:
        click.echo("[!] Passwords do not match")
        sys.exit(1)

    user.password = password1
    user.hash_password()
    database.commit()


@cli.command("create_role")
@click.option("-n", "--name", "name", required=True)
@click.option("-u", "--users", "users", multiple=True, required=True)
@click.option("-d", "--description", "description", default=[])
def create_role(name, users, description):
    """
    This command allows for the creation of a new role within Lemur
    """
    user_objs = []
    for u in users:
        user_obj = user_service.get_by_username(u)
        if user_obj:
            user_objs.append(user_obj)
        else:
            click.echo(f"[!] Cannot find user {u}")
            sys.exit(1)
    role_service.create(name, description=description, users=users)
    click.echo(f"[+] Created new role: {name}")


@cli.command("start", context_settings=dict(ignore_unknown_options=True, allow_extra_args=True))
def start():
    """
    This is the main Lemur server, it runs the flask app with gunicorn and
    uses any configuration options passed to it.


    You can pass all standard gunicorn flags to this command as if you were
    running gunicorn itself.

    For example:

    lemur start -w 4 -b 127.0.0.0:8002

    Will start gunicorn with 4 workers bound to 127.0.0.0:8002
    """
    from gunicorn.app.wsgiapp import WSGIApplication
    app = WSGIApplication()

    # run startup tasks on an app like object
    validate_conf(current_app, REQUIRED_VARIABLES)

    app.app_uri = "lemur:create_app()"

    return app.run()


@cli.command("create_config")
@click.option("-c", "--config", "config_path")
def create_config(config_path):
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

    click.echo(f"[+] Created a new configuration file {config_path}")


@cli.command("lock")
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
    click.echo("[!] Generating a new key...")

    key = Fernet.generate_key()

    if not os.path.exists(dest_dir):
        click.echo(f"[+] Creating encryption directory: {dest_dir}")
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(os.path.join(path, "decrypted")):
        for f in files:
            source = os.path.join(root, f)
            dest = os.path.join(dest_dir, f + ".enc")
            with open(source, "rb") as in_file, open(dest, "wb") as out_file:
                f = Fernet(key)
                data = f.encrypt(in_file.read())
                out_file.write(data)
                click.echo(
                    f"[+] Writing file: {dest} Source: {source}"
                )

    click.echo(f"[+] Keys have been encrypted with key {key}")


@cli.command("unlock")
def unlock(path=None):
    """
    Decrypts all of the files in a given directory with provided password.
    This is most commonly used during the startup sequence of Lemur
    allowing it to go from source code to something that can communicate
    with external services.

    Path defaults ~/.lemur/keys

    :param: path
    """
    key = click.prompt("[!] Please enter the encryption password", type=str)

    if not path:
        path = os.path.expanduser("~/.lemur/keys")

    dest_dir = os.path.join(path, "decrypted")
    source_dir = os.path.join(path, "encrypted")

    if not os.path.exists(dest_dir):
        click.echo(f"[+] Creating decryption directory: {dest_dir}")
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            source = os.path.join(source_dir, f)
            dest = os.path.join(dest_dir, ".".join(f.split(".")[:-1]))
            with open(source, "rb") as in_file, open(dest, "wb") as out_file:
                f = Fernet(key)
                data = f.decrypt(in_file.read())
                out_file.write(data)
                click.echo(
                    f"[+] Writing file: {dest} Source: {source}"
                )

    click.echo("[+] Keys have been unencrypted!")


@cli.command("publish_verisign_units")
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
                "name": f"Symantec {name} Unit Count",
                "tags": {},
                "value": value,
            }
        ]

        requests.post("http://localhost:8078/metrics", data=json.dumps(metric))


def main():

    cli.add_command(acme_cli, "acme")
    cli.add_command(certificate_cli, "certificate")
    cli.add_command(dns_provider_cli, "dns_providers")
    cli.add_command(db, "db")
    cli.add_command(notification_cli, "notify")
    cli.add_command(pending_certificate_cli, "pending_certs")
    cli.add_command(policy_cli, "policy")
    cli.add_command(report_cli, "report")
    cli.add_command(source_cli, "source")
    cli()


if __name__ == "__main__":
    main()
