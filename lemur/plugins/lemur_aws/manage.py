"""
.. module: lemur.plugins.lemur_aws.manage
    :synopsis: Module contains some often used and helpful classes that
    are used to deal with ELBs
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
import time

from flask.ext.script import Manager, Command, Option, prompt_bool

from lemur.certificates import service as certificate_service
from lemur.destinations import service as destination_service
from .elb import create_arn, check_duplicate_listener, update_listeners, create_new_listeners

manager = Manager(usage="Perform ELB operations")


class Update(Command):
    """
    Creates and provisions a certificate on an ELB based on command line arguments
    """

    option_list = (
        Option('-e', '--elb', dest='elb_name', required=True),
        Option('-a', '--account', dest='account', required=True),
        Option('-c', '--certificate', dest='certificate_name', required=True),
        Option('-r', '--region', dest='region', default='us-east-1'),
        Option('-d', '--dest-port', dest='dport', default=7002),
        Option('-s', '--source-port', dest='sport', default=443),
        Option('--dry-run', dest='dryrun', action='store_true')
    )

    def run(self, elb_name, certificate_name, account, region, dport, sport, dryrun):
        if dryrun:
            print("Starting ELB Update DRYRUN, changes will NOT be reflected to AWS!")

        certificate = certificate_service.get_by_name(certificate_name)

        if not certificate:
            print("[/] No certificate found with the name {name}".format(name=certificate_name))
            sys.exit(1)

        for dest in certificate.destinations:
            if dest.name == account:
                account_number = dest.plugin.get_option('accountNumber', dest.options)
                arn = create_arn(account_number, certificate.name)
                break
        else:
            choice = prompt_bool(
                '[!] Certificate {name} is not available in {account}, would you like to make it available?'.format(
                    name=certificate_name,
                    account=account
                )
            )

            if choice:
                dest = destination_service.get_by_label(account)
                if dest:
                    print("[+] Making {name} available in {account}".format(
                        name=certificate.name,
                        account=account
                    ))
                    if not dryrun:
                        certificate.destinations.append(dest)
                        sys.stdout("[!] Waiting 15secs so that certificate becomes available")
                        time.sleep(15)

                    account_number = dest.plugin.get_option('accountNumber', dest.options)
                    arn = create_arn(account_number, certificate.name)
                else:
                    print('[/] There is no destination with the label {account}, nothing to do here'.format(account=account))
                    sys.exit(0)

            else:
                print('[/] Certificate not available in ELB account, nothing to do here.')
                sys.exit(0)

        print('[+] Configuring elb {} from port {} to port {} in region {} with cert {}'
              .format(elb_name, sport, dport, region, arn))

        if not dryrun:
            if check_duplicate_listener(elb_name, region, account, sport, dport):
                print("[/] ELB {} already has a listener {}->{} Attempting update...".format(elb_name, sport, dport))
                update_listeners(account, region, elb_name, [(sport, dport, 'HTTPS', arn)])
            else:
                print("[/] Attempting create...".format(elb_name, sport, dport))
                create_new_listeners(account, region, elb_name, [(sport, dport, 'HTTPS', arn)])

        print("[/] Done!")


manager.add_command('update', Update())
