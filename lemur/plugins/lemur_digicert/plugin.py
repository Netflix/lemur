"""
.. module: lemur.plugins.lemur_digicert.digicert
    :platform: Unix
    :synopsis: This module is responsible for communicating with the DigiCert '
    Advanced API.
    :license: Apache, see LICENSE for more details.

    DigiCert CertCentral (v2 API) Documentation
    https://www.digicert.com/services/v2/documentation

    Original Implementation:
    Chris Dorros, github.com/opendns/lemur-digicert

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import time
import json
import arrow
import requests

import pem

from flask import current_app

from lemur.extensions import metrics
from lemur.plugins.bases import IssuerPlugin, SourcePlugin

from lemur.plugins import lemur_digicert as digicert


def signature_hash(signing_algorithm):
    """Converts Lemur's signing algorithm into a format DigiCert understands.

    :param signing_algorithm:
    :return: str digicert specific algorithm string
    """
    if not signing_algorithm:
        return current_app.config.get('DIGICERT_DEFAULT_SIGNING_ALGORITHM', 'sha256')

    if signing_algorithm == 'sha256WithRSA':
        return 'sha256'

    elif signing_algorithm == 'sha384WithRSA':
        return 'sha384'

    elif signing_algorithm == 'sha512WithRSA':
        return 'sha512'

    raise Exception('Unsupported signing algorithm.')


def determine_validity_years(end_date):
    """Given an end date determine how many years into the future that date is.

    :param end_date:
    :return: str validity in years
    """
    now = arrow.utcnow()
    then = arrow.get(end_date)

    if then < now.replace(years=+1):
        return 1
    elif then < now.replace(years=+2):
        return 2
    elif then < now.replace(years=+3):
        return 3

    raise Exception("DigiCert issued certificates cannot exceed three"
                    " years in validity")


def get_issuance(options):
    """Get the time range for certificates.

    :param options:
    :return:
    """
    end_date = arrow.get(options['validity_end'])
    validity_years = determine_validity_years(end_date)
    return end_date, validity_years


def process_options(options, csr):
    """Set the incoming issuer options to DigiCert fields/options.

    :param options:
    :param csr:
    :return: dict or valid DigiCert options
    """
    data = {
        "certificate":
            {
                "common_name": options['common_name'],
                "csr": csr.decode('utf-8'),
                "signature_hash":
                    signature_hash(options.get('signing_algorithm')),
            },
        "organization":
            {
                "id": current_app.config.get("DIGICERT_ORG_ID")
            },
    }

    # add SANs if present
    if options.get('extensions', 'sub_alt_names'):
        dns_names = []
        for san in options['extensions']['sub_alt_names']['names']:
            dns_names.append(san['value'])

        data['certificate']['dns_names'] = dns_names

    end_date, validity_years = get_issuance(options)
    data['custom_expiration_date'] = end_date.format('YYYY-MM-DD')
    data['validity_years'] = validity_years

    return data


def handle_response(response):
    """
    Handle the DigiCert API response and any errors it might have experienced.
    :param response:
    :return:
    """
    metrics.send('digicert_status_code_{0}'.format(response.status_code), 'counter', 1)

    if response.status_code not in [200, 201, 302, 301]:
        raise Exception(response.json()['message'])

    return response.json()


class DigiCertSourcePlugin(SourcePlugin):
    """Wrap the Digicert Certifcate API."""
    title = 'DigiCert'
    slug = 'digicert-source'
    description = "Enables the use of Digicert as a source of existing certificates."
    version = digicert.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        """Initialize source with appropriate details."""
        if not current_app.config.get('DIGICERT_API_KEY'):
            raise Exception("No Digicert API key found. Ensure that 'DIGICERT_API_KEY' is set in the Lemur conf.")

        self.session = requests.Session()
        self.session.headers.update(
            {
                'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
                'Content-Type': 'application/json'
            }
        )

        super(DigiCertSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self):
        pass


class DigiCertIssuerPlugin(IssuerPlugin):
    """Wrap the Digicert Issuer API."""

    title = 'DigiCert'
    slug = 'digicert-issuer'
    description = "Enables the creation of certificates by"
    "the DigiCert REST API."
    version = digicert.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        if not current_app.config.get('DIGICERT_API_KEY'):
            raise Exception("No Digicert API key found. Ensure that 'DIGICERT_API_KEY' is set in the Lemur conf.")

        self.session = requests.Session()
        self.session.headers.update(
            {
                'X-DC-DEVKEY': current_app.config.get('DIGICERT_API_KEY'),
                'Content-Type': 'application/json'
            }
        )

        super(DigiCertIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """Create a DigiCert certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        base_url = current_app.config.get('DIGICERT_URL')

        # make certificate request
        determinator_url = "{0}/services/v2/order/certificate/ssl".format(base_url)
        data = process_options(issuer_options, csr)
        response = self.session.post(determinator_url, data=json.dumps(data))
        order_id = response.json()['id']

        while True:
            # get order info
            order_url = "{0}/services/v2/order/certificate/{1}".format(base_url, order_id)
            response_data = handle_response(self.session.get(order_url))
            if response_data['status'] == 'issued':
                break
            time.sleep(10)

        certificate_id = response_data['certificate']['id']

        # retrieve certificate
        certificate_url = "{0}/services/v2/certificate/{1}/download/format/pem_all".format(base_url, certificate_id)
        root, intermediate, end_enitity = pem.parse(self.session.get(certificate_url).content)
        return str(end_enitity), str(intermediate)

    @staticmethod
    def create_authority(options):
        """Create an authority.

        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'digicert'}
        return current_app.config.get('DIGICERT_ROOT'), "", [role]
