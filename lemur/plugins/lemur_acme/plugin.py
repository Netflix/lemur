"""
.. module: lemur.plugins.lemur_acme.acme
    :platform: Unix
    :synopsis: This module is responsible for communicating with the VeriSign VICE 2.0 API.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from acme.client import Client
from acme import jose
from acme import messages

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_acme as acme


class ACMEIssuerPlugin(IssuerPlugin):
    title = 'Acme'
    slug = 'acme-issuer'
    description = 'Enables the creation of certificates via ACME CAs (including Let\'s Encrypt'
    version = acme.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        self.key = current_app.config.get('ACME_PUBLIC_KEY')
        self.acme_uri = current_app.config.get('ACME_URL')
        self.authzr_uri = '{}/acme/authz/1'.format(self.acme_uri)
        self.acme_email = current_app.config.get('ACME_EMAIL')
        self.acme_tel = current_app.config.get('ACME_TEL')
        self.contact = ('mailto:{}'.format(self.acme_email), 'tel:{}'.format(self.acme_tel))

        current_app.logger.debug("Registering with Lets Encrypt")

        directory = messages.Directory({
            messages.NewRegistration: '{}/acme/new-reg'.format(self.acme_uri),
            messages.Revocation: '{}/acme/revoke-cert'.format(self.acme_uri),
        })

        self.client = Client(directory=directory, key=self.key, alg=jose.RS256)
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_domains(options):
        """
        Fetches all domains currently requested
        :param options:
        :return:
        """
        domains = [options['commonName']]
        for name in options['extensions']['subAltName']['names']:
            domains.append(name)
        return domains

    def _get_challenges(self, options):
        domains = self._get_domains(options)
        challenges = dict()
        for domain in domains:
            challenges[domain] = self.client.request_domain_challenges(domain, self.authzr_uri)
        return challenges

    def _solve_challenges(self, challenges):
        for chall in challenges:
            print chall.token

    def create_certificate(self, csr, issuer_options):
        """
        Creates a ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        # Registration
        regr = self.client.register()

        regr.body.update(agreement=regr.terms_of_service, key=self.key, contact=self.contact)
        self.client.update_registration(regr, regr.update(body=regr.body))
        self.client.agree_to_tos(regr)

        challs = self._get_challenges(issuer_options)
        authzrs = self.solve_challenges(challs)

        cert = self.client.poll_and_request_issuance(csr, authzrs)

        current_app.logger.debug("Requesting a new acme certificate: {0}".format(issuer_options))

        return cert, acme.fetch_chain(cert)

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'acme'}
        return current_app.config.get('ACME_ROOT'), "", [role]
