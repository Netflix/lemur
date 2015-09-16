import sys
import time
from flask import current_app
from flask.ext.script import Manager, Command, Option

from boto.exception import BotoServerError
from sqlalchemy.orm.exc import NoResultFound

from lemur.plugins.lemur_aws import elb
from lemur.certificates.views import valid_authority
from lemur.destinations import service as destination_service
from lemur.users import service as user_service
from lemur.certificates import service as certificate_service

manager = Manager(usage="Perform deployment operations")


def _unicode(data):
    import sys

    if sys.version_info.major < 3:
        return data.decode('UTF-8')
    return data


def get_destination_account(destination_name):
    for destination in get_destinations(destination_name):
        if destination.plugin_name == 'aws-destination':

            account_number = destination.plugin.get_option('accountNumber', destination.options)
            return account_number

    sys.stderr.write("No destination AWS account provided, failing\n")
    sys.exit(1)


def get_destinations(destination_names):
    """

    :param destination_names:
    :return:
    """
    destinations = []

    for destination_name in destination_names:
        destination = destination_service.get_by_label(destination_name)

        if not destination:
            sys.stderr.write("Invalid destination specified: '{}'\nAborting...\n".format(destination_name))
            sys.exit(1)

        destinations.append(destination_service.get_by_label(destination_name))

    return destinations


def build_cert_options(self, destinations, notifications, description, owner, dns, authority):
    # convert argument lists to arrays, or empty sets
    """

    :param self:
    :param destinations:
    :param notifications:
    :param description:
    :param owner:
    :param dns:
    :param authority:
    :return:
    """
    destinations = self.get_destinations(destinations)
    if not destinations:
        sys.stderr.write("Valid destinations provided\n")
        sys.exit(1)

    # get the primary CN
    common_name = dns[0]

    # If there are more than one fqdn, add them as alternate names
    extensions = {}
    if len(dns) > 1:
        extensions['subAltNames'] = {'names': map(lambda x: {'nameType': 'DNSName', 'value': x}, dns)}

    try:
        authority = valid_authority({"name": authority})
    except NoResultFound:
        sys.stderr.write("Invalid authority specified: '{}'\naborting\n".format(authority))
        sys.exit(1)

    options = {
        # Convert from the Destination model to the JSON input expected further in the code
        'destinations': map(lambda x: {'id': x.id, 'label': x.label}, destinations),
        'description': description,
        'notifications': notifications,
        'commonName': common_name,
        'extensions': extensions,
        'authority': authority,
        'owner': owner,
        # defaults:
        'organization': current_app.config.get('LEMUR_DEFAULT_ORGANIZATION'),
        'organizationalUnit': current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT'),
        'country': current_app.config.get('LEMUR_DEFAULT_COUNTRY'),
        'state': current_app.config.get('LEMUR_DEFAULT_STATE'),
        'location': current_app.config.get('LEMUR_DEFAULT_LOCATION')
    }

    return options


class ELB(Command):
    """
    Creates and provisions a certificate on an ELB based on command line arguments
    """

    option_list = (
        Option('-d', '--dns', dest='dns', action='append', required=True, type=_unicode),
        Option('-e', '--elb', dest='elb_name', required=True, type=_unicode),
        Option('-o', '--owner', dest='owner', type=_unicode),
        Option('-a', '--authority', dest='authority', required=True, type=_unicode),
        Option('-s', '--description', dest='description', default=u'Command line provisioned keypair', type=_unicode),
        Option('-t', '--destination', dest='destinations', action='append', type=_unicode, required=True),
        Option('-n', '--notification', dest='notifications', action='append', type=_unicode, default=[]),
        Option('-r', '--region', dest='region', default=u'us-east-1', type=_unicode),
        Option('-p', '--dport', '--port', dest='dport', default=7002),
        Option('--src-port', '--source-port', '--sport', dest='sport', default=443),
        Option('--dry-run', dest='dryrun', action='store_true')
    )

    def configure_user(self, owner):
        from flask import g
        import lemur.users.service
        # get the first user by default
        if not g.user:
            g.user = lemur.users.service.get_all()[0]

        return g.user.username

    @staticmethod
    def get_destinations(destination_names):

        destinations = []

        for destination_name in destination_names:
            destination = destination_service.get_by_label(destination_name)

            if not destination:
                sys.stderr.write("Invalid destination specified: '{}'\nAborting...\n".format(destination_name))
                sys.exit(1)

            destinations.append(destination_service.get_by_label(destination_name))

        return destinations

    def run(self, dns, elb_name, owner, authority, description, notifications, destinations, region, dport, sport, dryrun):

        owner = user_service.get_by_username(owner)
        # make a config blob from the command line arguments
        cert_options = self.build_cert_options(
            destinations=destinations,
            notifications=notifications,
            description=description,
            owner=owner,
            dns=dns,
            authority=authority)

        aws_account = self.get_destination_account(destinations)

        if dryrun:
            import json

            cert_options['authority'] = cert_options['authority'].name
            sys.stdout.write('Will create certificate using options: {}\n'
                             .format(json.dumps(cert_options, sort_keys=True, indent=2)))
            sys.stdout.write('Will create listener {}->{} HTTPS using the new certificate to elb {}\n'
                             .format(sport, dport, elb_name))
            sys.exit(0)

        if self.check_duplicate_listener(elb_name, region, aws_account, sport, dport):
            sys.stderr.write("ELB {} already has a listener {}->{}\nAborting...\n".format(elb_name, sport, dport))
            sys.exit(1)

        # create the certificate
        try:
            sys.stdout.write('Creating certificate for {}\n'.format(cert_options['commonName']))
            cert = certificate_service.create(**cert_options)
        except Exception as e:
            if e.message == 'Duplicate certificate: a certificate with the same common name exists already':
                sys.stderr.write("Certificate already exists named: {}\n".format(dns[0]))
                sys.exit(1)
            raise e

        cert_arn = cert.get_arn(aws_account)
        sys.stderr.write('cert arn: {}\n'.format(cert_arn))

        sys.stderr.write('Configuring elb {} from port {} to port {} in region {} with cert {}\n'
                         .format(elb_name, sport, dport, region, cert_arn))

        delay = 1
        done = False
        retries = 5
        while not done and retries > 0:
            try:
                elb.create_new_listeners(aws_account, region, elb_name, [(sport, dport, 'HTTPS', cert_arn)])
            except BotoServerError as bse:
                # if the server returns ad error, the certificate
                if bse.error_code == 'CertificateNotFound':
                    sys.stderr.write('Certificate not available yet in the AWS account, waiting {}, {} retries left\n'
                                     .format(delay, retries))
                    time.sleep(delay)
                    delay *= 2
                    retries -= 1
                elif bse.error_code == 'DuplicateListener':
                    sys.stderr.write('ELB {} already has a listener {}->{}'.format(elb_name, sport, dport))
                    sys.exit(1)
                else:
                    raise bse
            else:
                done = True
