
"""
.. module: lemur.elbs.sync
    :platform: Unix
    :synopsis: This module attempts to sync with AWS and ensure that all elbs
    currently available in AWS are available in Lemur as well

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""

from flask import current_app
#from lemur.accounts import service as account_service
from lemur.elbs import service as elb_service
#from lemur.common.services.aws.elb import get_all_elbs, get_all_regions


def create_new(known, aws, account):
    new = 0
    for elb in aws:
        for n in known:
            if elb.name == n.name:
                break
        else:
            new += 1
            current_app.logger.debug("Creating {0}".format(elb.name))
            try:
                elb_service.create(account, elb)
            except AttributeError as e:
                current_app.logger.exception(e)
    return new


def remove_missing(known, aws):
    deleted = 0
    for ke in known:
        for elb in aws:
            if elb.name == ke.name:
                break
        else:
            deleted += 1
            current_app.logger.debug("Deleting {0}".format(ke.name))
            elb_service.delete(ke.id)
    return deleted


def sync_all_elbs():
    for account in account_service.get_all():
        regions = get_all_regions()
        for region in regions:
            current_app.logger.info("Importing ELBs from '{0}/{1}/{2}'... ".format(account.account_number, account.label, region))
            try:
                aws_elbs = get_all_elbs(account.account_number, region)
            except Exception as e:
                current_app.logger.error("Failed to get ELBS from '{0}/{1}/{2}' reason: {3}".format(
                    account.label, account.account_number, region, e.message)
                )
                continue

            known_elbs = elb_service.get_by_region_and_account(region, account.id)

            new_elbs = create_new(known_elbs, aws_elbs, account)
            current_app.logger.info(
                "Created {0} new ELBs in '{1}/{2}/{3}'...".format(
                    new_elbs, account.account_number, account.label, region))

            deleted_elbs = remove_missing(known_elbs, aws_elbs)
            current_app.logger.info(
                "Deleted {0} missing ELBs from '{1}/{2}/{3}'...".format(
                    deleted_elbs, account.account_number, account.label, region))
