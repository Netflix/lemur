"""
.. module: lemur.certificates.manage
    :copyright: (c) 2015 by netflix inc., see authors for more
    :license: apache, see license for more details.
.. moduleauthor:: kevin glisson <kglisson@netflix.com>
"""
import sys
import json
from flask import current_app
from flask.ext.script import Manager, Command, Option

from lemur.certificates import service
from lemur.authorities import service as authority_service
from lemur.users import service as user_service


manager = Manager(usage="Perform certificate operations")


def _unicode(data):
    import sys

    if sys.version_info.major < 3:
        return data.decode('UTF-8')
    return data


def _build_cert_options(destinations, notifications, description, owner, dns, authority):
    """
    Get command line parameters into something that Lemur can consume
    :param destinations:
    :param notifications:
    :param description:
    :param owner:
    :param dns:
    :param authority:
    :return:
    """
    # get the primary CN
    common_name = dns[0]

    # If there are more than one fqdn, add them as alternate names
    extensions = {}
    if len(dns) > 1:
        extensions['subAltNames'] = {'names': map(lambda x: {'nameType': 'DNSName', 'value': x}, dns)}

    options = {
        # Convert from the Destination model to the JSON input expected further in the code
        'destinations': map(lambda x: {'id': x.id, 'label': x.label}, destinations),
        'description': description,
        'notifications': notifications,
        'commonName': common_name,
        'extensions': extensions,
        'authority': authority,
        'owner': owner,
        'organization': _unicode(current_app.config.get('LEMUR_DEFAULT_ORGANIZATION')),
        'organizationalUnit': _unicode(current_app.config.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT')),
        'country': _unicode(current_app.config.get('LEMUR_DEFAULT_COUNTRY')),
        'state': _unicode(current_app.config.get('LEMUR_DEFAULT_STATE')),
        'location': _unicode(current_app.config.get('LEMUR_DEFAULT_LOCATION'))
    }

    return options


class ReIssue(Command):
    """
    Attempts to re-issue a given certificate
    """
    option_list = (
        Option('-n', '--name', dest='name', required=True),
        Option('--dry-run', dest='dryrun', action='store_true')
    )

    def run(self, name, dryrun):
        if dryrun:
            print("Starting Reissue DRYRUN, changes will NOT be reflected to Lemur!")


class Create(Command):
    """
    Creates a certificate based on command line arguments
    """
    option_list = (
        Option('-d', '--dns', dest='dns', action='append', type=_unicode, required=True),
        Option('-o', '--owner', dest='owner', required=True),
        Option('-c', '--creator', dest='creator', required=True),
        Option('-a', '--authority', dest='authority', required=True),
        Option('-s', '--description', dest='description', default=u'Command line provisioned keypair'),
        Option('-t', '--destination', dest='destinations', action='append', default=[]),
        Option('-n', '--notification', dest='notifications', action='append', default=[]),
        Option('--dry-run', dest='dryrun', action='store_true')
    )

    def run(self, dns, owner, creator, authority, description, notifications, destinations, dryrun):
        if dryrun:
            print("Starting Create DRYRUN, changes will NOT be reflected to Lemur!")

        cert_options = _build_cert_options(
            destinations=destinations,
            notifications=notifications,
            description=description,
            owner=owner,
            dns=dns,
            authority=authority)

        print("[+] Creating new certificate with the following options: ")
        print(json.dumps(cert_options, sort_keys=True, indent=4))
        user = user_service.get_by_email(creator)

        if not user:
            user = user_service.get_by_username(creator)

        if user:
            cert_options['user'] = user
        else:
            print("[/] the creator: {} could not be found".format(creator))
            sys.exit(1)

        if not dryrun:
            cert_options['authority'] = authority_service.get_by_name(cert_options['authority'])

            cert = service.create(**cert_options)
            print("[+] Created certificate: {name}".format(name=cert.name))

        print("[\] Done!")


manager.add_command("create", Create())
manager.add_command("reissue", ReIssue())
