from __future__ import unicode_literals    # at top of module

import arrow
from datetime import datetime, timedelta
from collections import Counter

import os
import sys
import base64
import time
import requests
import json

from tabulate import tabulate
from gunicorn.config import make_settings

from cryptography.fernet import Fernet

from flask import current_app
from flask.ext.script import Manager, Command, Option, prompt_pass
from flask.ext.migrate import Migrate, MigrateCommand, stamp
from flask_script.commands import ShowUrls, Clean, Server

from lemur import database
from lemur.extensions import metrics
from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.certificates import service as cert_service
from lemur.authorities import service as authority_service
from lemur.notifications import service as notification_service

from lemur.certificates.verify import verify_string
from lemur.sources import service as source_service

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

# Authentication Providers
ACTIVE_PROVIDERS = []

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
        # we use Fernet.generate_key to make sure that the key length is
        # compatible with Fernet
        encryption_key=Fernet.generate_key(),
        secret_token=base64.b64encode(os.urandom(KEY_LENGTH)),
        flask_secret_key=base64.b64encode(os.urandom(KEY_LENGTH)),
    )

    return output


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


class CreateUser(Command):
    """
    This command allows for the creation of a new user within Lemur.
    """
    option_list = (
        Option('-u', '--username', dest='username', required=True),
        Option('-e', '--email', dest='email', required=True),
        Option('-a', '--active', dest='active', default=True),
        Option('-r', '--roles', dest='roles', action='append', default=[])
    )

    def run(self, username, email, active, roles):
        role_objs = []
        for r in roles:
            role_obj = role_service.get_by_name(r)
            if role_obj:
                role_objs.append(role_obj)
            else:
                sys.stderr.write("[!] Cannot find role {0}\n".format(r))
                sys.exit(1)

        password1 = prompt_pass("Password")
        password2 = prompt_pass("Confirm Password")

        if password1 != password2:
            sys.stderr.write("[!] Passwords do not match!\n")
            sys.exit(1)

        user_service.create(username, password1, email, active, None, role_objs)
        sys.stdout.write("[+] Created new user: {0}\n".format(username))


class ResetPassword(Command):
    """
    This command allows you to reset a user's password.
    """
    option_list = (
        Option('-u', '--username', dest='username', required=True),
    )

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
            for setting, klass in settings.items() if klass.cli
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


def unicode_(data):
    import sys

    if sys.version_info.major < 3:
        return data.decode('UTF-8')
    return data


def print_certificate_details(details):
    """
    Print the certificate details with formatting.
    :param details:
    :return:
    """
    sys.stdout.write("[+] Re-issuing certificate with the following details:  \n")
    sys.stdout.write(
        "[+] Common Name: {common_name}\n"
        "[+] Subject Alternate Names: {sans}\n"
        "[+] Authority: {authority_name}\n"
        "[+] Validity Start: {validity_start}\n"
        "[+] Validity End: {validity_end}\n"
        "[+] Organization: {organization}\n"
        "[+] Organizational Unit: {organizational_unit}\n"
        "[+] Country: {country}\n"
        "[+] State: {state}\n"
        "[+] Location: {location}\n".format(
            common_name=details['common_name'],
            sans=",".join(x['value'] for x in details['extensions']['sub_alt_names']['names']),
            authority_name=details['authority'].name,
            validity_start=details['validity_start'].isoformat(),
            validity_end=details['validity_end'].isoformat(),
            organization=details['organization'],
            organizational_unit=details['organizational_unit'],
            country=details['country'],
            state=details['state'],
            location=details['location']
        )
    )


class RotateCertificate(Command):
    """
    Rotates certificate on all endpoints managed by Lemur.
    """
    option_list = (
        Option('-n', '--cert-name', dest='new_cert_name'),
        Option('-o', '--old-cert-name', dest='old_cert_name', required=True),
        Option('-c', '--commit', dest='commit', action='store_true', default=False)
    )

    def run(self, new_cert_name, old_cert_name, commit):
        from lemur.certificates.service import get_by_name, reissue_certificate, get_certificate_primitives
        from lemur.endpoints.service import rotate_certificate

        old_cert = get_by_name(old_cert_name)

        if not old_cert:
            sys.stdout.write("[-] No certificate found with name: {0}\n".format(old_cert_name))
            sys.exit(1)

        if new_cert_name:
            new_cert = get_by_name(new_cert_name)

            if not new_cert:
                sys.stdout.write("[-] No certificate found with name: {0}\n".format(old_cert_name))
                sys.exit(1)

        if commit:
            sys.stdout.write("[!] Running in COMMIT mode.\n")

        if not new_cert_name:
            sys.stdout.write("[!] No new certificate provided. Attempting to re-issue old certificate: {0}.\n".format(old_cert_name))

            details = get_certificate_primitives(old_cert)
            print_certificate_details(details)

            if commit:
                new_cert = reissue_certificate(old_cert, replace=True)
                sys.stdout.write("[+] Issued new certificate named: {0}\n".format(new_cert.name))

            sys.stdout.write("[+] Done! \n")

        if len(old_cert.endpoints) > 0:
            for endpoint in old_cert.endpoints:
                sys.stdout.write("[+] Certificate found deployed onto {0}\n ".format(endpoint.name))
                sys.stdout.write("[+] Rotating certificate from: {0} to: {1}\n ".format(old_cert_name, new_cert.name))

                if commit:
                    rotate_certificate(endpoint, new_cert_name)

                sys.stdout.write("[+] Done! \n")
        else:
            sys.stdout.write("[!] Certificate not found on any existing endpoints. Nothing to rotate.\n")


class ReissueCertificate(Command):
    """
    Reissues a certificate based on a given certificate.
    """
    option_list = (
        Option('-o', '--old-cert-name', dest='old_cert_name', required=True),
        Option('-c', '--commit', dest='commit', action='store_true', default=False)
    )

    def run(self, old_cert_name, commit):
        from lemur.certificates.service import get_by_name, reissue_certificate, get_certificate_primitives

        old_cert = get_by_name(old_cert_name)

        if not old_cert:
            sys.stdout.write("[-] No certificate found with name: {0}\n".format(old_cert_name))
            sys.exit(1)

        if commit:
            sys.stdout.write("[!] Running in COMMIT mode.\n")

        details = get_certificate_primitives(old_cert)
        print_certificate_details(details)

        if commit:
            new_cert = reissue_certificate(old_cert, replace=True)
            sys.stdout.write("[+] Issued new certificate named: {0}\n".format(new_cert.name))

        sys.stdout.write("[+] Done! \n")


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


@manager.command
def publish_unapproved_verisign_certificates():
    """
    Query the Verisign for any certificates that need to be approved.
    :return:
    """
    from lemur.plugins import plugins
    from lemur.extensions import metrics
    v = plugins.get('verisign-issuer')
    certs = v.get_pending_certificates()
    metrics.send('pending_certificates', 'gauge', certs)


class Report(Command):
    """
    Defines a set of reports to be run periodically against Lemur.
    """
    option_list = (
        Option('-n', '--name', dest='name', default=None, help='Name of the report to run.'),
        Option('-d', '--duration', dest='duration', default=356, help='Number of days to run the report'),
    )

    def run(self, name, duration):
        end = datetime.utcnow()
        start = end - timedelta(days=duration)

        if name == 'authority':
            self.certificates_issued(name, start, end)

        elif name == 'activeFQDNS':
            self.active_fqdns()

    @staticmethod
    def active_fqdns():
        """
        Generates a report that gives the number of active fqdns, but root domain.
        :return:
        """
        from lemur.certificates.service import get_all_certs
        sys.stdout.write("FQDN, Root Domain, Issuer, Total Length (days), Time until expiration (days)\n")
        for cert in get_all_certs():
            if not cert.expired:
                now = arrow.utcnow()
                ttl = now - cert.not_before
                total_length = cert.not_after - cert.not_before

                for fqdn in cert.domains:
                    root_domain = ".".join(fqdn.name.split('.')[-2:])
                    sys.stdout.write(", ".join([fqdn.name, root_domain, cert.issuer, str(total_length.days), str(ttl.days)]) + "\n")

    @staticmethod
    def certificates_issued(name=None, start=None, end=None):
        """
        Generates simple report of number of certificates issued by the authority, if no authority
        is specified report on total number of certificates.

        :param name:
        :param start:
        :param end:
        :return:
        """

        def _calculate_row(authority):
            day_cnt = Counter()
            month_cnt = Counter()
            year_cnt = Counter()

            for cert in authority.certificates:
                date = cert.date_created.date()
                day_cnt[date.day] += 1
                month_cnt[date.month] += 1
                year_cnt[date.year] += 1

            try:
                day_avg = int(sum(day_cnt.values()) / len(day_cnt.keys()))
            except ZeroDivisionError:
                day_avg = 0

            try:
                month_avg = int(sum(month_cnt.values()) / len(month_cnt.keys()))
            except ZeroDivisionError:
                month_avg = 0

            try:
                year_avg = int(sum(year_cnt.values()) / len(year_cnt.keys()))
            except ZeroDivisionError:
                year_avg = 0

            return [authority.name, authority.description, day_avg, month_avg, year_avg]

        rows = []
        if not name:
            for authority in authority_service.get_all():
                rows.append(_calculate_row(authority))

        else:
            authority = authority_service.get_by_name(name)

            if not authority:
                sys.stderr.write('[!] Authority {0} was not found.'.format(name))
                sys.exit(1)

            rows.append(_calculate_row(authority))

        sys.stdout.write(tabulate(rows, headers=["Authority Name", "Description", "Daily Average", "Monthy Average", "Yearly Average"]) + "\n")


class Sources(Command):
    """
    Defines a set of actions to take against Lemur's sources.
    """
    option_list = (
        Option('-s', '--sources', dest='source_strings', action='append', help='Sources to operate on.', required=True),
        Option('-a', '--action', choices=['sync', 'clean'], dest='action', help='Action to take on source.', required=True)
    )

    def run(self, source_strings, action):
        sources = []
        if not source_strings:
            table = []
            for source in source_service.get_all():
                table.append([source.label, source.active, source.description])

            sys.stdout.write(tabulate(table, headers=['Label', 'Active', 'Description']))
            sys.exit(1)

        elif 'all' in source_strings:
            sources = source_service.get_all()

        else:
            for source_str in source_strings:
                source = source_service.get_by_label(source_str)

                if not source:
                    sys.stderr.write("Unable to find specified source with label: {0}".format(source_str))

                sources.append(source)

        for source in sources:
            if action == 'sync':
                self.sync(source)

            if action == 'clean':
                self.clean(source)

    @staticmethod
    def sync(source):
        start_time = time.time()
        sys.stdout.write("[+] Staring to sync source: {label}!\n".format(label=source.label))

        user = user_service.get_by_username('lemur')

        try:
            source_service.sync(source, user)
            sys.stdout.write(
                "[+] Finished syncing source: {label}. Run Time: {time}\n".format(
                    label=source.label,
                    time=(time.time() - start_time)
                )
            )
        except Exception as e:
            current_app.logger.exception(e)

            sys.stdout.write(
                "[X] Failed syncing source {label}!\n".format(label=source.label)
            )

            metrics.send('sync_failed', 'counter', 1, metric_tags={'source': source.label})

    @staticmethod
    def clean(source):
        start_time = time.time()
        sys.stdout.write("[+] Staring to clean source: {label}!\n".format(label=source.label))
        source_service.clean(source)
        sys.stdout.write(
            "[+] Finished cleaning source: {label}. Run Time: {time}\n".format(
                label=source.label,
                time=(time.time() - start_time)
            )
        )


def main():
    manager.add_command("start", LemurServer())
    manager.add_command("runserver", Server(host='127.0.0.1', threaded=True))
    manager.add_command("clean", Clean())
    manager.add_command("show_urls", ShowUrls())
    manager.add_command("db", MigrateCommand)
    manager.add_command("init", InitializeApp())
    manager.add_command("create_user", CreateUser())
    manager.add_command("reset_password", ResetPassword())
    manager.add_command("create_role", CreateRole())
    manager.add_command("sources", Sources())
    manager.add_command("report", Report())
    manager.add_command("rotate_certificate", RotateCertificate())
    manager.add_command("reissue_certificate", ReissueCertificate())
    manager.run()

if __name__ == "__main__":
    main()
