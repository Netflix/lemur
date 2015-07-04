#!/usr/bin/env python
import os
import sys
import base64
from gunicorn.config import make_settings

from flask import current_app
from flask.ext.script import Manager, Command, Option, Group, prompt_pass
from flask.ext.migrate import Migrate, MigrateCommand, stamp
from flask_script.commands import ShowUrls, Clean, Server

from lemur import database
from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.accounts import service as account_service
from lemur.certificates import service as cert_service

from lemur.certificates.verify import verify_string
from lemur.certificates import sync
from lemur.elbs.sync import sync_all_elbs

from lemur import create_app
from lemur.common.crypto import encrypt, decrypt, lock, unlock

# Needed to be imported so that SQLAlchemy create_all can find our models
from lemur.users.models import User
from lemur.roles.models import Role
from lemur.authorities.models import Authority
from lemur.certificates.models import Certificate
from lemur.accounts.models import Account
from lemur.domains.models import Domain
from lemur.elbs.models import ELB
from lemur.listeners.models import Listener

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

#############
## General ##
#############

# These will need to be set to `True` if you are developing locally
CORS = False
debug = False

# You should consider storing these separately from your config
LEMUR_SECRET_TOKEN = '{secret_token}'
LEMUR_ENCRYPTION_KEY = '{encryption_key}'

# this is a list of domains as regexes that only admins can issue
LEMUR_RESTRICTED_DOMAINS = []

#################
## Mail Server ##
#################

# Lemur currently only supports SES for sending email, this address
# needs to be verified
LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []

#############
## Logging ##
#############

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"


##############
## Database ##
##############

SQLALCHEMY_DATABASE_URI = ''


#########
## AWS ##
#########

# Lemur will need STS assume role access to every account you want to monitor
#AWS_ACCOUNT_MAPPINGS = {{
#    '1111111111': 'myawsacount'
#}}

## This is useful if you know you only want to monitor one account
#AWS_REGIONS = ['us-east-1']

#LEMUR_INSTANCE_PROFILE = 'Lemur'

#############
## Issuers ##
#############

# These will be dependent on which 3rd party that Lemur is
# configured to use.

#CLOUDCA_URL = ''
#CLOUDCA_PEM_PATH = ''
#CLOUDCA_BUNDLE = ''

# number of years to issue if not specified
#CLOUDCA_DEFAULT_VALIDITY = 2

#VERISIGN_URL = ''
#VERISIGN_PEM_PATH = ''
#VERISIGN_FIRST_NAME = ''
#VERISIGN_LAST_NAME = ''
#VERSIGN_EMAIL = ''
"""

@MigrateCommand.command
def create():
    database.db.create_all()
    stamp(revision='head')


@manager.command
def lock():
    """
    Encrypts all of the files in the `keys` directory with the password
    given. This is a useful function to ensure that you do no check in
    your key files into source code in clear text.

    :return:
    """
    password = prompt_pass("Please enter the encryption password")
    lock(password)
    sys.stdout.write("[+] Lemur keys have been encrypted!\n")


@manager.command
def unlock():
    """
    Decrypts all of the files in the `keys` directory with the password
    given. This is most commonly used during the startup sequence of Lemur
    allowing it to go from source code to something that can communicate
    with external services.

    :return:
    """
    password = prompt_pass("Please enter the encryption password")
    unlock(password)
    sys.stdout.write("[+] Lemur keys have been unencrypted!\n")


@manager.command
def encrypt_file(source):
    """
    Utility to encrypt sensitive files, Lemur will decrypt these
    files when admin enters the correct password.

    Uses AES-256-CBC encryption
    """
    dest = source + ".encrypted"
    password = prompt_pass("Please enter the encryption password")
    password1 = prompt_pass("Please confirm the encryption password")
    if password != password1:
        sys.stdout.write("[!] Encryption passwords do not match!\n")
        return

    with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
        encrypt(in_file, out_file, password)

    sys.stdout.write("[+] Writing encryption files... {0}!\n".format(dest))


@manager.command
def decrypt_file(source):
    """
    Utility to decrypt, Lemur will decrypt these
    files when admin enters the correct password.

    Assumes AES-256-CBC encryption
    """
    # cleanup extensions a bit
    if ".encrypted" in source:
        dest = ".".join(source.split(".")[:-1]) + ".decrypted"
    else:
        dest = source + ".decrypted"

    password = prompt_pass("Please enter the encryption password")

    with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
        decrypt(in_file, out_file, password)

    sys.stdout.write("[+] Writing decrypted files... {0}!\n".format(dest))


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
        if cert.chain:
            status = verify_string(cert.body, cert.chain)
        else:
            status = verify_string(cert.body, "")

        cert.status = 'valid' if status else "invalid"
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
        secret_token=base64.b64encode(os.urandom(KEY_LENGTH))
    )

    return output


class Sync(Command):
    """
    Attempts to run several methods Certificate discovery. This is
    run on a periodic basis and updates the Lemur datastore with the
    information it discovers.
    """
    option_list = [
        Group(
            Option('-a', '--all', action="store_true"),
            Option('-b', '--aws', action="store_true"),
            Option('-d', '--cloudca', action="store_true"),
            Option('-s', '--source', action="store_true"),
            exclusive=True, required=True
        )
    ]

    def run(self, all, aws, cloudca, source):
        sys.stdout.write("[!] Starting to sync with external sources!\n")

        if all or aws:
            sys.stdout.write("[!] Starting to sync with AWS!\n")
            try:
                sync.aws()
                #sync_all_elbs()
                sys.stdout.write("[+] Finished syncing with AWS!\n")
            except Exception as e:
                sys.stdout.write("[-] Syncing with AWS failed!\n")

        if all or cloudca:
            sys.stdout.write("[!] Starting to sync with CloudCA!\n")
            try:
                sync.cloudca()
                sys.stdout.write("[+] Finished syncing with CloudCA!\n")
            except Exception as e:
                sys.stdout.write("[-] Syncing with CloudCA failed!\n")

            sys.stdout.write("[!] Starting to sync with Source Code!\n")

        if all or source:
            try:
                sync.source()
                sys.stdout.write("[+] Finished syncing with Source Code!\n")
            except Exception as e:
                sys.stdout.write("[-] Syncing with Source Code failed!\n")

            sys.stdout.write("[+] Finished syncing with external sources!\n")


class InitializeApp(Command):
    """
    This command will bootstrap our database with any accounts as
    specified by our config.

    Additionally a Lemur user will be created as a default user
    and be used when certificates are discovered by Lemur.
    """
    def run(self):
        create()
        user = user_service.get_by_username("lemur")

        if not user:
            sys.stdout.write("We need to set Lemur's password to continue!\n")
            password1 = prompt_pass("Password")
            password2 = prompt_pass("Confirm Password")

            if password1 != password2:
                sys.stderr.write("[!] Passwords do not match!\n")
                sys.exit(1)

            role = role_service.get_by_name('admin')

            if role:
                sys.stdout.write("[-] Admin role already created, skipping...!\n")
            else:
                # we create an admin role
                role = role_service.create('admin', description='this is the lemur administrator role')
                sys.stdout.write("[+] Created 'admin' role\n")

            user_service.create("lemur", password1, 'lemur@nobody', True, None, [role])
            sys.stdout.write("[+] Added a 'lemur' user and added it to the 'admin' role!\n")

        else:
            sys.stdout.write("[-] Default user has already been created, skipping...!\n")

        if current_app.config.get('AWS_ACCOUNT_MAPPINGS'):
            for account_name, account_number in current_app.config.get('AWS_ACCOUNT_MAPPINGS').items():
                account = account_service.get_by_account_number(account_number)

                if not account:
                    account_service.create(account_number, label=account_name)
                    sys.stdout.write("[+] Added new account {0}:{1}!\n".format(account_number, account_name))
                else:
                    sys.stdout.write("[-] Account already exists, skipping...!\n")

        sys.stdout.write("[/] Done!\n")


class CreateUser(Command):
    """
    This command allows for the creation of a new user within Lemur
    """
    option_list = (
        Option('-u', '--username', dest='username', required=True),
        Option('-e', '--email', dest='email', required=True),
        Option('-a', '--active', dest='active', default=True),
        Option('-r', '--roles', dest='roles', default=[])
    )

    def run(self, username, email, active, roles):
        role_objs = []
        for r in roles:
            role_obj = role_service.get_by_name(r)
            if role_obj:
                role_objs.append(role_obj)
            else:
                sys.stderr.write("[!] Cannot find role {0}".format(r))
                sys.exit(1)

        password1 = prompt_pass("Password")
        password2 = prompt_pass("Confirm Password")

        if password1 != password2:
            sys.stderr.write("[!] Passwords do not match")
            sys.exit(1)

        user_service.create(username, password1, email, active, None, role_objs)
        sys.stdout.write("[+] Created new user: {0}".format(username))


class CreateRole(Command):
    """
    This command allows for the creation of a new role within Lemur
    """
    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('-u', '--users', dest='users', default=[]),
        Option('-d', '--description', dest='description', required=True)
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

    sys.stdout.write("Created a new configuration file {0}\n".format(config_path))


def main():
    manager.add_command("start", LemurServer())
    manager.add_command("runserver", Server(host='127.0.0.1'))
    manager.add_command("clean", Clean())
    manager.add_command("show_urls", ShowUrls())
    manager.add_command("db", MigrateCommand)
    manager.add_command("init", InitializeApp())
    manager.add_command('create_user', CreateUser())
    manager.add_command('create_role', CreateRole())
    manager.add_command("sync", Sync())
    manager.run()


if __name__ == "__main__":
    main()
