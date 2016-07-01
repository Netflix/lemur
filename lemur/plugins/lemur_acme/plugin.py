"""
.. module: lemur.plugins.lemur_acme.acme
    :platform: Unix
    :synopsis: This module is responsible for communicating with a ACME CA.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Snippets from https://raw.githubusercontent.com/alex/letsencrypt-aws/master/letsencrypt-aws.py

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
"""
from flask import current_app

from acme.client import Client
from acme import jose
from acme import messages

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import OpenSSL.crypto

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_acme as acme

from .route53 import delete_txt_record, create_txt_record, wait_for_change


def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


def start_dns_challenge(acme_client, host):
    authz = acme_client.request_domain_challenges(
        host, acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    change_id = create_txt_record(
        dns_challenge.validation_domain_name(host),
        dns_challenge.validation(acme_client.key),

    )
    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
    )


def complete_dns_challenge(acme_client, authz_record):
    wait_for_change(authz_record.change_id)

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
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )
    return pem_certificate, pem_certificate_chain


def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def setup_acme_client():
    key = current_app.config.get('ACME_PRIVATE_KEY').strip()
    acme_email = current_app.config.get('ACME_EMAIL')
    acme_tel = current_app.config.get('ACME_TEL')
    acme_directory_url = current_app.config.get('ACME_DIRECTORY_URL'),
    contact = ('mailto:{}'.format(acme_email), 'tel:{}'.format(acme_tel))

    key = serialization.load_pem_private_key(
        key, password=None, backend=default_backend()
    )
    return acme_client_for_private_key(acme_directory_url, key)


def acme_client_for_private_key(acme_directory_url, private_key):
    return Client(
        acme_directory_url, key=jose.JWKRSA(key=private_key)
    )


def register(email):
    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(current_app.config('ACME_DIRECTORY_URL'), private_key)

    registration = acme_client.register(
        messages.NewRegistration.from_data(email=email)
    )
    acme_client.agree_to_tos(registration)
    return private_key


def get_domains(options):
    """
    Fetches all domains currently requested
    :param options:
    :return:
    """
    domains = [options['common_name']]
    for name in options['extensions']['sub_alt_name']['names']:
        domains.append(name)
    return domains


def get_authorizations(acme_client, domains):
    authorizations = []
    try:
        for domain in domains:
            authz_record = start_dns_challenge(acme_client, domain)
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(acme_client, authz_record)
    finally:
        for authz_record in authorizations:
            dns_challenge = authz_record.dns_challenge
            delete_txt_record(
                authz_record.change_id,
                dns_challenge.validation_domain_name(authz_record.host),
                dns_challenge.validation(acme_client.key),
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
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates a ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        current_app.logger.debug("Requesting a new acme certificate: {0}".format(issuer_options))
        acme_client = setup_acme_client()
        domains = get_domains(issuer_options)
        authorizations = get_authorizations(acme_client, domains)
        pem_certificate, pem_certificate_chain = request_certificate(acme_client, authorizations, csr)
        return pem_certificate, pem_certificate_chain

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
