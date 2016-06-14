"""
.. module: lemur.plugins.lemur_aws_letsencrypt.AWSLetsenrypt
    :platform: Unix
    :synopsis: This module is responsible for communicating with the Let's encrypt's  ACME API as well as
    route 53 AWS boto API in order to answer DNS challenge.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Used code from https://raw.githubusercontent.com/alex/letsencrypt-aws/master/letsencrypt-aws.py

    By Mikhail Khodorovskiy

    The plugin issues certificates using Let's Encrypt authority to Route53 controlled domains.

    Example policy for Lemur Route53 IAM permissions where YOUR_DOMAIN_ZONE_ID is the zone id for the certificate domain:

    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "route53:ListHostedZones",
                "route53:GetChange",
                "route53:GetChangeDetails"
            ],
            "Resource": [
                "*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "route53:*"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/<YOUR_DOMAIN_ZONE_ID>"
            ],
            "Effect": "Allow"
        }
    ]
}

"""

import time

from flask import current_app
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL.crypto
import boto.route53
from boto.route53.record import ResourceRecordSets
from boto.route53.status import Status

import acme.challenges
import acme.client
import acme.jose
from lemur.plugins.bases import IssuerPlugin

DNS_TTL = 30

class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, route53_change_id,
                 route53_zone_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.route53_change_id = route53_change_id
        self.route53_zone_id = route53_zone_id

def generate_cert(csr, acme_client, route53_client, hosts):

    authorizations = []
    try:
        for host in hosts:
            authz_record = start_dns_challenge(
                acme_client, route53_client, host
            )
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(
                acme_client, route53_client, authz_record
            )

        return request_certificate(
            acme_client, authorizations, csr
        )

    finally:
        for authz_record in authorizations:
            dns_challenge = authz_record.dns_challenge
            change_txt_record(
                route53_client,
                "DELETE",
                authz_record.route53_zone_id,
                dns_challenge.validation_domain_name(authz_record.host),
                dns_challenge.validation(acme_client.key),
            )


def change_txt_record(route53_client, action, zone_id, domain, value):
    change_set = ResourceRecordSets(route53_client, zone_id)
    changes1 = change_set.add_change(action, domain, type="TXT", ttl=DNS_TTL)
    changes1.add_value('\"' + value + '\"')
    return change_set.commit().ChangeInfo

def start_dns_challenge(acme_client, route53_client, host):
    current_app.logger.debug(
        "request-acme-challenge: host: " + host
    )

    authz = acme_client.request_domain_challenges(
        host, acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    zone_id = find_zone_id_for_domain(route53_client, host)

    current_app.logger.debug(
        "create-txt-record: host: " + host
    )

    change_id = change_txt_record(
        route53_client,
        "CREATE",
        zone_id,
        dns_challenge.validation_domain_name(host),
        dns_challenge.validation(acme_client.key),
    )
    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
        zone_id,
    )


def complete_dns_challenge(acme_client, route53_client, authz_record):

    current_app.logger.debug(
        "wait-for-route53: host: " +  authz_record.host
    )

    wait_for_route53_change(route53_client, authz_record.route53_change_id)

    response = authz_record.dns_challenge.response(acme_client.key)

    current_app.logger.debug(
        "local-validation: host: " + authz_record.host
    )

    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.host,
        acme_client.key.public_key()
    )
    if not verified:
        raise ValueError("Failed verification")

    current_app.logger.debug(
        "answer-challenge: host: " + authz_record.host
    )

    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(acme_client, authorizations, csr):
    current_app.logger.debug("request-certs")
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM,
                csr
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

def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
                        len(combo) == 1 and
                    isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def find_zone_id_for_domain(route53_client, domain):
    for zone in route53_client.get_zones():
        # This assumes that zones are returned sorted by specificity,
        # meaning in the following order:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        if (
                    domain.endswith(zone.name) or
                    (domain + ".").endswith(zone.name)
        ):
            return zone.id


def wait_for_route53_change(route53_client, change):
    status = Status(route53_client, change)
    while status.update() == "PENDING":
        time.sleep(5)


def acme_client_for_private_key(acme_directory_url, private_key):
    return acme.client.Client(
        # TODO: support EC keys, when acme.jose does.
        acme_directory_url, key=acme.jose.JWKRSA(key=private_key)
    )

def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

def get_acme_client(url, email):
    current_app.logger.debug("acme-register.generate-key")

    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(url, private_key)

    current_app.logger.debug("acme-register.register " + email)

    registration = acme_client.register(
        acme.messages.NewRegistration.from_data(email=email)
    )

    current_app.logger.debug("acme-register.agree-to-tos")

    acme_client.agree_to_tos(registration)

    return acme_client

def get_subject_alternative_hosts(options):
    hosts = []
    if options.get('extensions'):
        for k, v in options.get('extensions', {}).items():
            if k == 'subAltNames':
                for name in v['names']:
                    if name['nameType'] == 'DNSName':
                        hosts = hosts + [name['value']]
    return hosts

class AWSLetsEncryptIssuerPlugin(IssuerPlugin):
    title = 'AWSLetsEncrypt'
    slug = 'awsletsencrypt-issuer'
    description = 'Enables the creation of Letsenchrypt certs using AWS Route53.'

    author = 'Mikhail Khodorovskiy'
    author_url = 'https://github.com/mik373/lemur'

    def __init__(self, *args, **kwargs):
        super(AWSLetsEncryptIssuerPlugin, self).__init__(*args, **kwargs)

    # noinspection PyMethodOverriding
    def create_certificate(self, csr, issuer_options):
        """
        Creates a Lets encrypt certificate

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """

        hosts = [issuer_options['commonName']] + get_subject_alternative_hosts(issuer_options)

        route53_client = boto.connect_route53()

        directory_url = current_app.config.get('LETS_ENCRYPT_DEFAULT_DIRECTORY')
        email = issuer_options['owner']

        acme_client = get_acme_client(directory_url, email)
        # (csr, acme_client, route53_client, hosts)

        pem_certificate, pem_certificate_chain = generate_cert(csr, acme_client, route53_client, hosts)

        return pem_certificate, pem_certificate_chain

    # noinspection PyMethodOverriding
    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'awsletsencrypt'}

        return current_app.config.get('LETS_ENCRYPT_ROOT'), "", [role]