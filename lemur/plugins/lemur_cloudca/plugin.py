"""
.. module: lemur.common.services.issuers.plugins.cloudca
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import re
import ssl
import base64
from json import dumps

import arrow
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError

from flask import current_app

from lemur.exceptions import LemurException
from lemur.plugins.bases import IssuerPlugin, SourcePlugin
from lemur.plugins import lemur_cloudca as cloudca

from lemur.authorities import service as authority_service


class CloudCAException(LemurException):
    def __init__(self, message):
        self.message = message
        current_app.logger.error(self)

    def __str__(self):
        return repr("CloudCA request failed: {0}".format(self.message))


class CloudCAHostNameCheckingAdapter(HTTPAdapter):
    def cert_verify(self, conn, url, verify, cert):
        super(CloudCAHostNameCheckingAdapter, self).cert_verify(conn, url, verify, cert)
        conn.assert_hostname = False


def remove_none(options):
    """
    Simple function that traverse the options and removed any None items
    CloudCA really dislikes null values.

    :param options:
    :return:
    """
    new_dict = {}
    for k, v in options.items():
        if v:
            new_dict[k] = v

    # this is super hacky and gross, cloudca doesn't like null values
    if new_dict.get('extensions'):
        if len(new_dict['extensions']['subAltNames']['names']) == 0:
            del new_dict['extensions']['subAltNames']

    return new_dict


def get_default_issuance(options):
    """
    Gets the default time range for certificates

    :param options:
    :return:
    """
    if not options.get('validityStart') and not options.get('validityEnd'):
        start = arrow.utcnow()
        options['validityStart'] = start.floor('second').isoformat()
        options['validityEnd'] = start.replace(years=current_app.config.get('CLOUDCA_DEFAULT_VALIDITY'))\
            .ceil('second').isoformat()
    return options


def convert_to_pem(der):
    """
    Converts DER to PEM Lemur uses PEM internally

    :param der:
    :return:
    """
    decoded = base64.b64decode(der)
    return ssl.DER_cert_to_PEM_cert(decoded)


def convert_date_to_utc_time(date):
    """
    Converts a python `datetime` object to the current date + current time in UTC.

    :param date:
    :return:
    """
    d = arrow.get(date)
    return arrow.utcnow().replace(day=d.naive.day).replace(month=d.naive.month).replace(year=d.naive.year)\
        .replace(microsecond=0)


def process_response(response):
    """
    Helper function that processes responses from CloudCA.

    :param response:
    :return: :raise CloudCAException:
    """
    if response.status_code == 200:
        res = response.json()
        if res['returnValue'] != 'success':
            current_app.logger.debug(res)
            if res.get('data'):
                raise CloudCAException(" ".join([res['returnMessage'], res['data']['dryRunResultMessage']]))
            else:
                raise CloudCAException(res['returnMessage'])
    else:
        raise CloudCAException("There was an error with your request: {0}".format(response.status_code))

    return response.json()


def get_auth_data(ca_name):
    """
    Creates the authentication record needed to authenticate a user request to CloudCA.

    :param ca_name:
    :return: :raise CloudCAException:
    """
    role = authority_service.get_authority_role(ca_name)
    if role:
        return {
            "authInfo": {
                "credType": "password",
                "credentials": {
                    "username": role.username,
                    "password": role.password  # we only decrypt when we need to
                }

            }
        }

    raise CloudCAException("You do not have the required role to issue certificates from {0}".format(ca_name))


class CloudCA(object):
    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        self.session.mount('https://', CloudCAHostNameCheckingAdapter())
        self.url = current_app.config.get('CLOUDCA_URL')

        if current_app.config.get('CLOUDCA_PEM_PATH') and current_app.config.get('CLOUDCA_BUNDLE'):
            self.session.cert = current_app.config.get('CLOUDCA_PEM_PATH')
            self.ca_bundle = current_app.config.get('CLOUDCA_BUNDLE')
        else:
            current_app.logger.warning(
                "No CLOUDCA credentials found, lemur will be unable to request certificates from CLOUDCA"
            )

        super(CloudCA, self).__init__(*args, **kwargs)

    def post(self, endpoint, data):
        """
        HTTP POST to CloudCA

        :param endpoint:
        :param data:
        :return:
        """
        data = dumps(dict(data.items() + get_auth_data(data['caName']).items()))

        # we set a low timeout, if cloudca is down it shouldn't bring down
        # lemur
        try:
            response = self.session.post(self.url + endpoint, data=data, timeout=10, verify=self.ca_bundle)
        except ConnectionError:
            raise Exception("Could not talk to CloudCA, is it up?")

        return process_response(response)

    def get(self, endpoint):
        """
        HTTP GET to CloudCA

        :param endpoint:
        :return:
        """
        try:
            response = self.session.get(self.url + endpoint, timeout=10, verify=self.ca_bundle)
        except ConnectionError:
            raise Exception("Could not talk to CloudCA, is it up?")

        return process_response(response)

    def random(self, length=10):
        """
        Uses CloudCA as a decent source of randomness.

        :param length:
        :return:
        """
        endpoint = '/v1/random/{0}'.format(length)
        response = self.session.get(self.url + endpoint, verify=self.ca_bundle)
        return response

    def get_authorities(self):
        """
        Retrieves authorities that were made outside of Lemur.

        :return:
        """
        endpoint = '{0}/listCAs'.format(current_app.config.get('CLOUDCA_API_ENDPOINT'))
        authorities = []
        for ca in self.get(endpoint)['data']['caList']:
            try:
                authorities.append(ca['caName'])
            except AttributeError:
                current_app.logger.error("No authority has been defined for {}".format(ca['caName']))

        return authorities


class CloudCAIssuerPlugin(IssuerPlugin, CloudCA):
    title = 'CloudCA'
    slug = 'cloudca-issuer'
    description = 'Enables the creation of certificates from the cloudca API.'
    version = cloudca.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    def create_authority(self, options):
        """
        Creates a new certificate authority

        :param options:
        :return:
        """
        # this is weird and I don't like it
        endpoint = '{0}/createCA'.format(current_app.config.get('CLOUDCA_API_ENDPOINT'))
        options['caDN']['email'] = options['ownerEmail']

        if options['caType'] == 'subca':
            options = dict(options.items() + self.auth_data(options['caParent']).items())

        options['validityStart'] = convert_date_to_utc_time(options['validityStart']).isoformat()
        options['validityEnd'] = convert_date_to_utc_time(options['validityEnd']).isoformat()

        try:
            response = self.session.post(self.url + endpoint, data=dumps(remove_none(options)), timeout=10,
                                         verify=self.ca_bundle)
        except ConnectionError:
            raise Exception("Could not communicate with CloudCA, is it up?")

        json = process_response(response)
        roles = []

        for cred in json['data']['authInfo']:
            role = {
                'username': cred['credentials']['username'],
                'password': cred['credentials']['password'],
                'name': "_".join([options['caName'], cred['credentials']['username']])
            }
            roles.append(role)

        if options['caType'] == 'subca':
            cert = convert_to_pem(json['data']['certificate'])
        else:
            cert = convert_to_pem(json['data']['rootCertificate'])

        intermediates = []
        for i in json['data']['intermediateCertificates']:
            intermediates.append(convert_to_pem(i))

        return cert, "".join(intermediates), roles,

    def create_certificate(self, csr, options):
        """
        Creates a new certificate from cloudca

        If no start and end date are specified the default issue range
        will be used.

        :param csr:
        :param options:
        """
        endpoint = '{0}/enroll'.format(current_app.config.get('CLOUDCA_API_ENDPOINT'))
        # lets default to two years if it's not specified
        # we do some last minute data massaging
        options = get_default_issuance(options)

        cloudca_options = {
            'extensions': options['extensions'],
            'validityStart': convert_date_to_utc_time(options['validityStart']).isoformat(),
            'validityEnd': convert_date_to_utc_time(options['validityEnd']).isoformat(),
            'creator': options['creator'],
            'ownerEmail': options['owner'],
            'caName': options['authority'].name,
            'csr': csr,
            'comment': re.sub(r'^[\w\-\s]+$', '', options['description'])
        }

        response = self.post(endpoint, remove_none(cloudca_options))

        # we return a concatenated list of intermediate because that is what aws
        # expects
        cert = convert_to_pem(response['data']['certificate'])

        intermediates = [convert_to_pem(response['data']['rootCertificate'])]
        for i in response['data']['intermediateCertificates']:
            intermediates.append(convert_to_pem(i))

        return cert, "".join(intermediates),


class CloudCASourcePlugin(SourcePlugin, CloudCA):
    title = 'CloudCA'
    slug = 'cloudca-source'
    description = 'Discovers all SSL certificates in CloudCA'
    version = cloudca.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    options = {
        'pollRate': {'type': 'int', 'default': '60'}
    }

    def get_certificates(self, options, **kwargs):
        certs = []
        for authority in self.get_authorities():
            certs += self.get_cert(ca_name=authority)
        return certs

    def get_cert(self, ca_name=None, cert_handle=None):
        """
        Returns a given cert from CloudCA.

        :param ca_name:
        :param cert_handle:
        :return:
        """
        endpoint = '{0}/getCert'.format(current_app.config.get('CLOUDCA_API_ENDPOINT'))
        response = self.session.post(self.url + endpoint, data=dumps({'caName': ca_name}), timeout=10,
                                     verify=self.ca_bundle)
        raw = process_response(response)

        certs = []
        for c in raw['data']['certList']:
            cert = convert_to_pem(c['certValue'])

            intermediates = []
            for i in c['intermediateCertificates']:
                intermediates.append(convert_to_pem(i))

            certs.append({
                'public_certificate': cert,
                'intermediate_certificate': "\n".join(intermediates),
                'owner': c['ownerEmail']
            })

        return certs
