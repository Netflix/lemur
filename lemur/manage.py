import os
import sys
import base64
import time
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
        secret_token=base64.b64encode(os.urandom(KEY_LENGTH)),
        flask_secret_key=base64.b64encode(os.urandom(KEY_LENGTH)),
    )

    return output


@manager.option('-s', '--sources', dest='labels', default='', required=False)
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

                if labels:
                    sys.stdout.write("[+] Staring to sync sources: {labels}!\n".format(labels=labels))
                    labels = labels.split(",")
                else:
                    sys.stdout.write("[+] Starting to sync ALL sources!\n")

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

        sys.stdout.write("[+] Creating expiration email notifications!\n")
        sys.stdout.write("[!] Using {recipients} as specified by LEMUR_SECURITY_TEAM_EMAIL for notifications\n")

        intervals = current_app.config.get("LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS")
        sys.stdout.write(
            "[!] Creating {num} notifications for {intervals} days as specified by LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS\n".format(
                num=len(intervals),
                intervals=",".join([str(x) for x in intervals])
            )
        )

        recipients = current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL')
        notification_service.create_default_expiration_notifications("DEFAULT_SECURITY", recipients=recipients)

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


class ProvisionELB(Command):
    """
    Creates and provisions a certificate on an ELB based on a json blob
    """

    option_list = (
        Option('-d', '--dns', dest='dns', required=True),
        Option('-e', '--elb', dest='elb', required=True),
        Option('-o', '--owner', dest='owner'),
        Option('-a', '--authority', dest='authority', required=True),
        Option('-s', '--description', dest='description'),
        Option('-t', '--destinations', dest='destinations'),
        Option('-n', '--notifications', dest='notifications')
    )

    def _configure_user(self, owner):
        from flask import g
        import lemur.users.service

        # grab the user
        g.user = lemur.users.service.get_by_username(owner)
        # get the first user by default
        if not g.user:
            g.user = lemur.users.service.get_all()[0]

        return unicode(g.user.username)

    def _build_cert_options(self, destinations, notifications, description, owner, dns, authority):
        # convert argument lists to arrays, or empty sets
        destinations = [] if not destinations else destinations.split(',')
        notifications = [] if not notifications else notifications.split(',')

        # set a default description
        description = u'Command line provisioned keypair' if not description else unicode(description)

        owner = unicode(owner)

        dns = dns.split(',')

        # get the primary CN
        cn = unicode(dns[0])

        # IF there are more, add them as alternate name
        extensions = {}
        if len(dns) > 1:
            sub_alt_names = []

            for alt_name in dns[1:]:
                sub_alt_names.append({'nameType': 'DNSName', 'value': unicode(alt_name)})

            extensions['subAltNames'] = {'names': sub_alt_names}

        sys.stdout.write("subNames: {}\n".format(extensions))
        sys.stdout.write("cn: {} is a {}\n".format(cn, cn.__class__))

        from lemur.certificates.views import valid_authority

        authority = valid_authority({"name": authority})

        options = {
            'destinations': destinations,
            'description': description,
            'notifications': notifications,
            'commonName': cn,
            'extensions': extensions,
            'authority': authority,
            'owner': owner,
            # defaults:
            'organization': u'Netflix',
            'organizationalUnit': u'Operations',
            'country': u'US',
            'state': u'California',
            'location': u'Los Gatos'
        }

        return options

    def run(self, dns, elb, owner, authority, description, notifications, destinations):
        from lemur.certificates import service

        # configure the owner if we can find it, or go for default, and put it in the global
        owner = self._configure_user(owner)

        # make a config blob from the command line arguments
        cert_options = self._build_cert_options(
            destinations=destinations, notifications=notifications, description=description,
            owner=owner, dns=dns, authority=authority)

        sys.stdout.write("cert options: {}\n".format(cert_options))

        # create the certificate
        cert = service.create(**cert_options)
        sys.stdout.write("cert {}".format(cert))


def main():
    manager.add_command("start", LemurServer())
    manager.add_command("runserver", Server(host='127.0.0.1'))
    manager.add_command("clean", Clean())
    manager.add_command("show_urls", ShowUrls())
    manager.add_command("db", MigrateCommand)
    manager.add_command("init", InitializeApp())
    manager.add_command("create_user", CreateUser())
    manager.add_command("create_role", CreateRole())
    manager.add_command("provision_elb", ProvisionELB())
    manager.run()

if __name__ == "__main__":
    main()
