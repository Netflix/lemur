from __future__ import unicode_literals    # at top of module

import os
import sys
import base64
import time
import requests
import json
from gunicorn.config import make_settings

from cryptography.fernet import Fernet

from lockfile import LockFile, LockTimeout

from flask import current_app
from flask.ext.script import Manager, Command, Option, prompt_pass
from flask.ext.migrate import Migrate, MigrateCommand, stamp
from flask_script.commands import ShowUrls, Clean, Server

from lemur import database
from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.certificates import service as cert_service
from lemur.sources import service as source_service
from lemur.notifications import service as notification_service

from lemur.certificates.verify import verify_string
from lemur.sources.service import sync

from lemur import create_app

from lemur.deployment.manage import manager as deployment_manager
from lemur.certificates.manage import manager as certificate_manager
from lemur.roles.manage import manager as role_manager
from lemur.destinations.manage import manager as destination_manager
from lemur.users.manage import manager as user_manager


# Needed to be imported so that SQLAlchemy create_all can find our models
from lemur.users.models import User  # noqa
from lemur.roles.models import Role  # noqa
from lemur.authorities.models import Authority  # noqa
from lemur.certificates.models import Certificate  # noqa
from lemur.destinations.models import Destination  # noqa
from lemur.domains.models import Domain  # noqa
from lemur.notifications.models import Notification  # noqa
from lemur.sources.models import Source  # noqa


manager = Manager(create_app)
manager.add_option('-c', '--config', dest='config')

migrate = Migrate(create_app)

KEY_LENGTH = 40
DEFAULT_CONFIG_PATH = '~/.lemur/lemur.conf.py'
DEFAULT_SETTINGS = 'lemur.conf.server'
SETTINGS_ENVVAR = 'LEMUR_CONF'


CONFIG_TEMPLATE = """
# This is just Python which means you can inherit and tweak settings

import os
_basedir = os.path.abspath(os.path.dirname(__file__))

ADMINS = frozenset([''])

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
debug = False

# this is the secret key used by flask session management
SECRET_KEY = '{flask_secret_key}'

# You should consider storing these separately from your config
LEMUR_TOKEN_SECRET = '{secret_token}'
LEMUR_ENCRYPTION_KEY = '{encryption_key}'

# this is a list of domains as regexes that only admins can issue
LEMUR_RESTRICTED_DOMAINS = []

# Mail Server

LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []

# Certificate Defaults

LEMUR_DEFAULT_COUNTRY = ''
LEMUR_DEFAULT_STATE = ''
LEMUR_DEFAULT_LOCATION = ''
LEMUR_DEFAULT_ORGANIZATION = ''
LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = ''


# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"


# Database

# modify this if you are not using a local database
SQLALCHEMY_DATABASE_URI = 'postgresql://lemur:lemur@localhost:5432/lemur'


# AWS

#LEMUR_INSTANCE_PROFILE = 'Lemur'

# Issuers

# These will be dependent on which 3rd party that Lemur is
# configured to use.

# CLOUDCA_URL = ''
# CLOUDCA_PEM_PATH = ''
# CLOUDCA_BUNDLE = ''

# number of years to issue if not specified
# CLOUDCA_DEFAULT_VALIDITY = 2

# VERISIGN_URL = ''
# VERISIGN_PEM_PATH = ''
# VERISIGN_FIRST_NAME = ''
# VERISIGN_LAST_NAME = ''
# VERSIGN_EMAIL = ''
"""


@MigrateCommand.command
def create():
    database.db.create_all()
    stamp(revision='head')


@MigrateCommand.command
def drop_all():
    database.db.drop_all()


@manager.command
def check_revoked():
    """
    Function attempts to update Lemur's internal cache with revoked
    certificates. This is called periodically by Lemur. It checks both
    CRLs and OCSP to see if a certificate is revoked. If Lemur is unable
    encounters an issue with verification it marks the certificate status
    as `unknown`.
    """
    for cert in cert_service.get_all_certs():
        try:
            if cert.chain:
                status = verify_string(cert.body, cert.chain)
            else:
                status = verify_string(cert.body, "")

            cert.status = 'valid' if status else 'invalid'
        except Exception as e:
            cert.status = 'unknown'
        database.update(cert)


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
        encryption_key=base64.b64encode(os.urandom(KEY_LENGTH)),
        secret_token=base64.b64encode(os.urandom(KEY_LENGTH)),
        flask_secret_key=base64.b64encode(os.urandom(KEY_LENGTH)),
    )

    return output


@manager.option('-s', '--sources', dest='labels')
def sync_sources(labels):
    """
    Attempts to run several methods Certificate discovery. This is
    run on a periodic basis and updates the Lemur datastore with the
    information it discovers.
    """
    if not labels:
        sys.stdout.write("Active\tLabel\tDescription\n")
        for source in source_service.get_all():
            sys.stdout.write(
                "{active}\t{label}\t{description}!\n".format(
                    label=source.label,
                    description=source.description,
                    active=source.active
                )
            )
    else:
        start_time = time.time()
        lock_file = "/tmp/.lemur_lock"
        sync_lock = LockFile(lock_file)

        while not sync_lock.i_am_locking():
            try:
                sync_lock.acquire(timeout=10)    # wait up to 10 seconds

                sys.stdout.write("[+] Staring to sync sources: {labels}!\n".format(labels=labels))
                labels = labels.split(",")

                if labels[0] == 'all':
                    sync()
                else:
                    sync(labels=labels)

                sys.stdout.write(
                    "[+] Finished syncing sources. Run Time: {time}\n".format(
                        time=(time.time() - start_time)
                    )
                )
            except LockTimeout:
                sys.stderr.write(
                    "[!] Unable to acquire file lock on {file}, is there another sync running?\n".format(
                        file=lock_file
                    )
                )
                sync_lock.break_lock()
                sync_lock.acquire()
                sync_lock.release()

        sync_lock.release()


@manager.command
def notify():
    """
    Runs Lemur's notification engine, that looks for expired certificates and sends
    notifications out to those that bave subscribed to them.

    :return:
    """
    sys.stdout.write("Starting to notify subscribers about expiring certificates!\n")
    count = notification_service.send_expiration_notifications()
    sys.stdout.write(
        "Finished notifying subscribers about expiring certificates! Sent {count} notifications!\n".format(
            count=count
        )
    )


class InitializeApp(Command):
    """
    This command will bootstrap our database with any destinations as
    specified by our config.

    Additionally a Lemur user will be created as a default user
    and be used when certificates are discovered by Lemur.
    """
    option_list = (
        Option('-p', '--password', dest='password'),
    )

    def run(self, password):
        create()
        user = user_service.get_by_username("lemur")

        if not user:
            if not password:
                sys.stdout.write("We need to set Lemur's password to continue!\n")
                password = prompt_pass("Password")
                password1 = prompt_pass("Confirm Password")

                if password != password1:
                    sys.stderr.write("[!] Passwords do not match!\n")
                    sys.exit(1)

            role = role_service.get_by_name('admin')

            if role:
                sys.stdout.write("[-] Admin role already created, skipping...!\n")
            else:
                # we create an admin role
                role = role_service.create('admin', description='this is the lemur administrator role')
                sys.stdout.write("[+] Created 'admin' role\n")

            user_service.create("lemur", password, 'lemur@nobody', True, None, [role])
            sys.stdout.write("[+] Added a 'lemur' user and added it to the 'admin' role!\n")

        else:
            sys.stdout.write("[-] Default user has already been created, skipping...!\n")

        sys.stdout.write("[+] Creating expiration email notifications!\n")
        sys.stdout.write("[!] Using {0} as specified by LEMUR_SECURITY_TEAM_EMAIL for notifications\n".format("LEMUR_SECURITY_TEAM_EMAIL"))

        intervals = current_app.config.get("LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS", [])
        sys.stdout.write(
            "[!] Creating {num} notifications for {intervals} days as specified by LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS\n".format(
                num=len(intervals),
                intervals=",".join([str(x) for x in intervals])
            )
        )

        recipients = current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL')
        notification_service.create_default_expiration_notifications("DEFAULT_SECURITY", recipients=recipients)

        sys.stdout.write("[/] Done!\n")


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
    description = 'Run the app within Gunicorn'

    def get_options(self):
        settings = make_settings()
        options = (
            Option(*klass.cli, action=klass.action)
            for setting, klass in settings.iteritems() if klass.cli
        )

        return options

    def run(self, *args, **kwargs):
        from gunicorn.app.wsgiapp import WSGIApplication

        app = WSGIApplication()
        app.app_uri = 'lemur:create_app(config="{0}")'.format(kwargs.get('config'))

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
    with open(config_path, 'w') as f:
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
        path = os.path.expanduser('~/.lemur/keys')

    dest_dir = os.path.join(path, "encrypted")
    sys.stdout.write("[!] Generating a new key...\n")

    key = Fernet.generate_key()

    if not os.path.exists(dest_dir):
        sys.stdout.write("[+] Creating encryption directory: {0}\n".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(os.path.join(path, 'decrypted')):
        for f in files:
            source = os.path.join(root, f)
            dest = os.path.join(dest_dir, f + ".enc")
            with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
                f = Fernet(key)
                data = f.encrypt(in_file.read())
                out_file.write(data)
                sys.stdout.write("[+] Writing file: {0} Source: {1}\n".format(dest, source))

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
        path = os.path.expanduser('~/.lemur/keys')

    dest_dir = os.path.join(path, "decrypted")
    source_dir = os.path.join(path, "encrypted")

    if not os.path.exists(dest_dir):
        sys.stdout.write("[+] Creating decryption directory: {0}\n".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            source = os.path.join(source_dir, f)
            dest = os.path.join(dest_dir, ".".join(f.split(".")[:-1]))
            with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
                f = Fernet(key)
                data = f.decrypt(in_file.read())
                out_file.write(data)
                sys.stdout.write("[+] Writing file: {0} Source: {1}\n".format(dest, source))

    sys.stdout.write("[+] Keys have been unencrypted!\n")


@manager.command
def publish_verisign_units():
    """
    Simple function that queries verisign for API units and posts the mertics to
    Atlas API for other teams to consume.
    :return:
    """
    from lemur.plugins import plugins
    v = plugins.get('verisign-issuer')
    units = v.get_available_units()

    metrics = {}
    for item in units:
        if item['@type'] in metrics.keys():
            metrics[item['@type']] += int(item['@remaining'])
        else:
            metrics.update({item['@type']: int(item['@remaining'])})

    for name, value in metrics.items():
        metric = [
            {
                "timestamp": 1321351651,
                "type": "GAUGE",
                "name": "Symantec {0} Unit Count".format(name),
                "tags": {},
                "value": value
            }
        ]

        requests.post('http://localhost:8078/metrics', data=json.dumps(metric))


def main():
    manager.add_command("start", LemurServer())
    manager.add_command("runserver", Server(host='127.0.0.1'))
    manager.add_command("clean", Clean())
    manager.add_command("show_urls", ShowUrls())
    manager.add_command("db", MigrateCommand)
    manager.add_command("init", InitializeApp())
    manager.add_command("deploy", deployment_manager)
    manager.add_command("certificates", certificate_manager)
    manager.add_command("roles", role_manager)
    manager.add_command("destinations", destination_manager)
    manager.add_command("users", user_manager)
    manager.run()

if __name__ == "__main__":
    main()
