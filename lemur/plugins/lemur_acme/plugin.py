"""
.. module: lemur.plugins.lemur_acme.plugin
    :platform: Unix
    :synopsis: This module is responsible for communicating with an ACME CA.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Snippets from https://raw.githubusercontent.com/alex/letsencrypt-aws/master/letsencrypt-aws.py

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
"""
import josepy as jose

from flask import current_app

from acme.client import Client
from acme import messages
from acme import challenges

from lemur.common.utils import generate_private_key

import OpenSSL.crypto

from lemur.common.utils import validate_conf
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_acme as acme


def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, challenges.DNS01)
        ):
            yield combo[0]


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


def start_dns_challenge(acme_client, account_number, host, dns_provider):
    current_app.logger.debug("Starting DNS challenge for {0}".format(host))
    authz = acme_client.request_domain_challenges(host)

    [dns_challenge] = find_dns_challenge(authz)

    change_id = dns_provider.create_txt_record(
        dns_challenge.validation_domain_name(host),
        dns_challenge.validation(acme_client.key),
        account_number
    )

    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
    )


def complete_dns_challenge(acme_client, account_number, authz_record, dns_provider):
    dns_provider.wait_for_dns_change(authz_record.change_id, account_number=account_number)

    response = authz_record.dns_challenge.response(acme_client.key)

    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.host,
        acme_client.key.public_key()
    )

    if not verified:
        raise ValueError("Failed verification")

    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(acme_client, authorizations, csr):
    cert_response, _ = acme_client.poll_and_request_issuance(
        jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM,
                csr
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )

    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    ).decode('utf-8')

    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert.decode("utf-8"))
        for cert in acme_client.fetch_chain(cert_response)
    ).decode('utf-8')

    current_app.logger.debug("{0} {1}".format(type(pem_certificate). type(pem_certificate_chain)))
    return pem_certificate, pem_certificate_chain


def setup_acme_client():
    email = current_app.config.get('ACME_EMAIL')
    tel = current_app.config.get('ACME_TEL')
    directory_url = current_app.config.get('ACME_DIRECTORY_URL')
    contact = ('mailto:{}'.format(email), 'tel:{}'.format(tel))

    key = jose.JWKRSA(key=generate_private_key('RSA2048'))

    current_app.logger.debug("Connecting with directory at {0}".format(directory_url))
    client = Client(directory_url, key)

    registration = client.register(
        messages.NewRegistration.from_data(email=email)
    )

    current_app.logger.debug("Connected: {0}".format(registration.uri))

    client.agree_to_tos(registration)
    return client, registration


def get_domains(options):
    """
    Fetches all domains currently requested
    :param options:
    :return:
    """
    current_app.logger.debug("Fetching domains")

    domains = [options['common_name']]
    if options.get('extensions'):
        for name in options['extensions']['sub_alt_names']['names']:
            domains.append(name)

    current_app.logger.debug("Got these domains: {0}".format(domains))
    return domains


def get_authorizations(acme_client, account_number, domains, dns_provider):
    authorizations = []
    try:
        for domain in domains:
            authz_record = start_dns_challenge(acme_client, account_number, domain, dns_provider)
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(acme_client, account_number, authz_record, dns_provider)
    finally:
        for authz_record in authorizations:
            dns_challenge = authz_record.dns_challenge
            dns_provider.delete_txt_record(
                authz_record.change_id,
                account_number,
                dns_challenge.validation_domain_name(authz_record.host),
                dns_challenge.validation(acme_client.key)
            )

    return authorizations


class ACMEIssuerPlugin(IssuerPlugin):
    title = 'Acme'
    slug = 'acme-issuer'
    description = 'Enables the creation of certificates via ACME CAs (including Let\'s Encrypt)'
    version = acme.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        required_vars = [
            'ACME_DIRECTORY_URL',
            'ACME_TEL',
            'ACME_EMAIL',
            'ACME_AWS_ACCOUNT_NUMBER',
            'ACME_ROOT'
        ]

        validate_conf(current_app, required_vars)
        self.dns_provider_name = current_app.config.get('ACME_DNS_PROVIDER', 'route53')
        current_app.logger.debug("Using DNS provider: {0}".format(self.dns_provider_name))
        self.dns_provider = __import__(self.dns_provider_name, globals(), locals(), [], 1)
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates an ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        current_app.logger.debug("Requesting a new acme certificate: {0}".format(issuer_options))
        acme_client, registration = setup_acme_client()
        account_number = current_app.config.get('ACME_AWS_ACCOUNT_NUMBER')
        domains = get_domains(issuer_options)
        authorizations = get_authorizations(acme_client, account_number, domains, self.dns_provider)
        pem_certificate, pem_certificate_chain = request_certificate(acme_client, authorizations, csr)
        # TODO add external ID (if possible)
        return pem_certificate, pem_certificate_chain, None

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
