"""
.. module: lemur.plugins.lemur_cfssl.plugin
    :platform: Unix
    :synopsis: This module is responsible for communicating with the CFSSL private CA.
    :copyright: (c) 2016 by Thomson Reuters
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Charles Hendrie <chad.hendrie@tr.com>
"""

import json
import requests

from flask import current_app

from cryptography import x509

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_cfssl as cfssl


class CfsslIssuerPlugin(IssuerPlugin):
    title = 'CFSSL'
    slug = 'cfssl-issuer'
    description = 'Enables the creation of certificates by CFSSL private CA'
    version = cfssl.VERSION

    author = 'Charles Hendrie'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        super(CfsslIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates a CFSSL certificate.

        :param csr:
        :param issuer_options:
        :return:
        """
        current_app.logger.info("Requesting a new cfssl certificate with csr: {0}".format(csr))

        url = "{0}{1}".format(current_app.config.get('CFSSL_URL'), '/api/v1/cfssl/sign')
        server_usage = x509.extensions.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])

        data = {'certificate_request': csr}

        # Workaround since cfssl ignores csr Extended keys
        #    Assumes your cfssl config file has 'server' in profiles list
        if issuer_options['extensions']['extended_key_usage'] == server_usage:
            data['profile'] = 'server'

        data = json.dumps(data)

        response = self.session.post(url, data=data.encode(encoding='utf_8', errors='strict'))
        response_json = json.loads(response.content.decode('utf_8'))
        cert = response_json['result']['certificate']

        return cert, current_app.config.get('CFSSL_INTERMEDIATE'),

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'cfssl'}
        return current_app.config.get('CFSSL_ROOT'), "", [role]
