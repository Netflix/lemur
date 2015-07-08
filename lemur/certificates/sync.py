"""
.. module: sync
    :platform: Unix
    :synopsis: This module contains various certificate syncing operations.
    Because of the nature of the SSL environment there are multiple ways
    a certificate could be created without Lemur's knowledge. Lemur attempts
    to 'sync' with as many different datasources as possible to try and track
    any certificate that may be in use.

    This include querying AWS for certificates attached to ELBs, querying our own
    internal CA for certificates issued. As well as some rudimentary source code
    scraping that attempts to find certificates checked into source code.

    These operations are typically run on a periodic basis from either the command
    line or a cron job.

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import requests
from bs4 import BeautifulSoup

from flask import current_app

from lemur.users import service as user_service
from lemur.accounts import service as account_service
from lemur.certificates import service as cert_service
from lemur.certificates.models import Certificate, get_name_from_arn
from lemur.common.services.aws.iam import get_all_server_certs
from lemur.common.services.aws.iam import get_cert_from_arn

from lemur.plugins.base import plugins

def aws():
    """
    Attempts to retrieve all certificates located in known AWS accounts
    :raise e:
    """
    new = 0
    updated = 0

    # all certificates 'discovered' by lemur are tracked by the lemur
    # user
    user = user_service.get_by_email('lemur@nobody')

    # we don't need to check regions as IAM is a global service
    for account in account_service.get_all():
        certificate_bodies = []
        try:
            cert_arns = get_all_server_certs(account.account_number)
        except Exception as e:
            current_app.logger.error("Failed to to get Certificates from '{}/{}' reason {}".format(
                account.label, account.account_number, e.message)
            )
            raise e

        current_app.logger.info("found {} certs from '{}/{}' ... ".format(
            len(cert_arns), account.account_number, account.label)
        )

        for cert in cert_arns:
            cert_body = get_cert_from_arn(cert.arn)[0]
            certificate_bodies.append(cert_body)
            existing = cert_service.find_duplicates(cert_body)

            if not existing:
                cert_service.import_certificate(
                    **{'owner': 'secops@netflix.com',
                       'creator': 'Lemur',
                       'name': get_name_from_arn(cert.arn),
                       'account': account,
                       'user': user,
                       'public_certificate': cert_body
                    }
                )
                new += 1

            elif len(existing) == 1: # we check to make sure we know about the current account for this certificate
                for e_account in existing[0].accounts:
                    if e_account.account_number == account.account_number:
                        break
                else: # we have a new account
                    existing[0].accounts.append(account)
                    updated += 1

            else:
                current_app.logger.error(
                    "Multiple certificates with the same body found, unable to correctly determine which entry to update"
                )

        # make sure we remove any certs that have been removed from AWS
        cert_service.disassociate_aws_account(certificate_bodies, account)
        current_app.logger.info("found {} new certificates in aws {}".format(new, account.label))


def cloudca():
    """
    Attempts to retrieve all certificates that are stored in CloudCA
    """
    user = user_service.get_by_email('lemur@nobody')
    # sync all new certificates/authorities not created through lemur
    issuer = plugins.get('cloudca')
    authorities = issuer.get_authorities()
    total = 0
    new = 1
    for authority in authorities:
        certs = issuer.get_cert(ca_name=authority)
        for cert in certs:
            total += 1
            cert['user'] = user
            existing = cert_service.find_duplicates(cert['public_certificate'])
            if not existing:
                new += 1
                try:
                    cert_service.import_certificate(**cert)
                except NameError as e:
                    current_app.logger.error("Cannot import certificate {0}".format(cert))

    current_app.logger.debug("Found {0} total certificates in cloudca".format(total))
    current_app.logger.debug("Found {0} new certificates in cloudca".format(new))


def source():
    """
    Attempts to track certificates that are stored in Source Code
    """
    new = 0
    keywords = ['"--- Begin Certificate ---"']
    endpoint = current_app.config.get('LEMUR_SOURCE_SEARCH')
    maxresults = 25000

    current_app.logger.info("Searching {0} for new certificates".format(endpoint))

    for keyword in keywords:
        current_app.logger.info("Looking for keyword: {0}".format(keyword))
        url = "{}/source/s?n={}&start=1&sort=relevancy&q={}&project=github%2Cperforce%2Cstash".format(endpoint, maxresults, keyword)

        current_app.logger.debug("Request url: {0}".format(url))
        r = requests.get(url, timeout=20)

        if r.status_code != 200:
            current_app.logger.error("Unable to retrieve: {0} Status Code: {1}".format(url, r.status_code))
            continue

        soup = BeautifulSoup(r.text, "lxml")
        results = soup.find_all(title='Download')
        for result in results:
            parts = result['href'].split('/')
            path = "/".join(parts[:-1])
            filename = parts[-1:][0]
            r = requests.get("{0}{1}/{2}".format(endpoint, path, filename))

            if r.status_code != 200:
                current_app.logger.error("Unable to retrieve: {0} Status Code: {1}".format(url, r.status_code))
                continue

            try:
                # validate we have a real certificate
                cert = Certificate(r.content)
                # do a lookup to see if we know about this certificate
                existing = cert_service.find_duplicates(r.content)
                if not existing:
                    current_app.logger.debug(cert.name)
                    cert_service.import_certificate()
                    new += 1
            except Exception as e:
                current_app.logger.debug("Could not parse the following 'certificate': {0} Reason: {1}".format(r.content, e))
