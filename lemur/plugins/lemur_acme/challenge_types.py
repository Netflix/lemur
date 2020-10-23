"""
.. module: lemur.plugins.lemur_acme.plugin
    :platform: Unix
    :synopsis: This module contains the different challenge types for ACME implementations
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Mathias Petermann <mathias.petermann@projektfokus.ch>
"""
import datetime
import json

import OpenSSL
from acme import challenges
from flask import current_app

from lemur.dns_providers import service as dns_provider_service
from lemur.extensions import metrics, sentry

from lemur.authorizations import service as authorization_service
from lemur.exceptions import LemurException, InvalidConfiguration
from lemur.plugins.base import plugins
from lemur.destinations import service as destination_service
from lemur.destinations.models import Destination
from lemur.plugins.lemur_acme.acme_handlers import AcmeHandler, AcmeDnsHandler


class AcmeChallengeMissmatchError(LemurException):
    pass


class AcmeChallenge(object):
    """
    This is the base class, all ACME challenges will need to extend, allowing for future extendability
    """

    def create_certificate(self, csr, issuer_options):
        """
        Create the new certificate, using the provided CSR and issuer_options.
        Right now this is basically a copy of the create_certificate methods in the AcmeHandlers, but should be cleaned
        and tried to make use of the deploy and cleanup methods

        :param csr:
        :param issuer_options:
        :return:
        """
        pass

    def deploy(self, challenge, acme_client, validation_target):
        """
        In here the challenge validation is fetched and deployed somewhere that it can be validated by the provider

        :param self:
        :param challenge: the challenge object, must match for the challenge implementation
        :param acme_client: an already bootstrapped acme_client, to avoid passing all issuer_options and so on
        :param validation_target: an identifier for the validation target, e.g. the name of a DNS provider
        """
        raise NotImplementedError

    def cleanup(self, challenge, acme_client, validation_target):
        """
        Ideally the challenge should be cleaned up, after the validation is done
        :param challenge: Needed to identify the challenge to be removed
        :param acme_client: an already bootstrapped acme_client, to avoid passing all issuer_options and so on
        :param validation_target: Needed to remove the validation
        """
        raise NotImplementedError


class AcmeHttpChallenge(AcmeChallenge):
    challengeType = challenges.HTTP01

    def create_certificate(self, csr, issuer_options):
        """
        Creates an ACME certificate using the HTTP-01 challenge.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        self.acme = AcmeHandler()
        authority = issuer_options.get("authority")
        acme_client, registration = self.acme.setup_acme_client(authority)

        orderr = acme_client.new_order(csr)

        chall = []
        for authz in orderr.authorizations:
            # Choosing challenge.
            # authz.body.challenges is a set of ChallengeBody objects.
            for i in authz.body.challenges:
                # Find the supported challenge.
                if isinstance(i.chall, challenges.HTTP01):
                    chall.append(i)

        if len(chall) == 0:
            raise Exception('HTTP-01 challenge was not offered by the CA server.')
        else:
            validation_target = None
            for option in json.loads(issuer_options["authority"].options):
                if option["name"] == "tokenDestination":
                    validation_target = option["value"]

            if validation_target is None:
                raise Exception('No token_destination configured for this authority. Cant complete HTTP-01 challenge')

        for challenge in chall:
            response = self.deploy(challenge, acme_client, validation_target)

            acme_client.answer_challenge(challenge, response)

        current_app.logger.info("Uploaded HTTP-01 challenge tokens, trying to poll and finalize the order")

        finalized_orderr = acme_client.finalize_order(orderr, datetime.datetime.now() + datetime.timedelta(seconds=90))

        pem_certificate = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, finalized_orderr.fullchain_pem
            ),
        ).decode()

        if current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA", False) \
                and datetime.datetime.now() < datetime.datetime.strptime(
                current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA_EXPIRATION_DATE", "17/03/21"), '%d/%m/%y'):
            pem_certificate_chain = current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA")
        else:
            pem_certificate_chain = finalized_orderr.fullchain_pem[
                                    len(pem_certificate):  # noqa
                                    ].lstrip()

        # validation is a random string, we use it as external id, to make it possible to implement revoke_certificate
        return pem_certificate, pem_certificate_chain, None

    def deploy(self, challenge, acme_client, validation_target):

        if not isinstance(challenge.chall, challenges.HTTP01):
            raise AcmeChallengeMissmatchError(
                'The provided challenge is not of type HTTP01, but instead of type {}'.format(
                    challenge.__class__.__name__))

        destination = destination_service.get(validation_target)

        if destination is None:
            raise Exception(
                'Couldn\'t find the destination with name {}. Cant complete HTTP01 challenge'.format(validation_target))

        destination_plugin = plugins.get(destination.plugin_name)

        response, validation = challenge.response_and_validation(acme_client.net.key)

        destination_plugin.upload_acme_token(challenge.chall.path, validation, destination.options)
        current_app.logger.info("Uploaded HTTP-01 challenge token.")

        return response

    def cleanup(self, challenge, acme_client, validation_target):
        pass


class AcmeDnsChallenge(AcmeChallenge):
    challengeType = challenges.DNS01

    def __init__(self):
        self.dns_providers_for_domain = {}
        try:
            self.all_dns_providers = dns_provider_service.get_all_dns_providers()
        except Exception as e:
            metrics.send("AcmeHandler_init_error", "counter", 1)
            sentry.captureException()
            current_app.logger.error(f"Unable to fetch DNS Providers: {e}")
            self.all_dns_providers = []

    def create_certificate(self, csr, issuer_options):
        """
        Creates an ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        self.acme = AcmeDnsHandler()
        authority = issuer_options.get("authority")
        create_immediately = issuer_options.get("create_immediately", False)
        acme_client, registration = self.acme.setup_acme_client(authority)
        dns_provider = issuer_options.get("dns_provider", {})

        if dns_provider:
            dns_provider_options = dns_provider.options
            credentials = json.loads(dns_provider.credentials)
            current_app.logger.debug(
                "Using DNS provider: {0}".format(dns_provider.provider_type)
            )
            dns_provider_plugin = __import__(
                dns_provider.provider_type, globals(), locals(), [], 1
            )
            account_number = credentials.get("account_id")
            provider_type = dns_provider.provider_type
            if provider_type == "route53" and not account_number:
                error = "Route53 DNS Provider {} does not have an account number configured.".format(
                    dns_provider.name
                )
                current_app.logger.error(error)
                raise InvalidConfiguration(error)
        else:
            dns_provider = {}
            dns_provider_options = None
            account_number = None
            provider_type = None

        domains = self.acme.get_domains(issuer_options)
        if not create_immediately:
            # Create pending authorizations that we'll need to do the creation
            dns_authorization = authorization_service.create(
                account_number, domains, provider_type
            )
            # Return id of the DNS Authorization
            return None, None, dns_authorization.id

        authorizations = self.acme.get_authorizations(
            acme_client,
            account_number,
            domains,
            dns_provider_plugin,
            dns_provider_options,
        )
        self.acme.finalize_authorizations(
            acme_client,
            account_number,
            dns_provider_plugin,
            authorizations,
            dns_provider_options,
        )
        pem_certificate, pem_certificate_chain = self.acme.request_certificate(
            acme_client, authorizations, csr
        )
        # TODO add external ID (if possible)
        return pem_certificate, pem_certificate_chain, None

    def deploy(self, challenge, acme_client, validation_target):
        pass

    def cleanup(self, authorizations, acme_client, validation_target):
        """
        Best effort attempt to delete DNS challenges that may not have been deleted previously. This is usually called
        on an exception

        :param authorizations: all the authorizations to be cleaned up
        :param acme_client: an already bootstrapped acme_client, to avoid passing all issuer_options and so on
        :param validation_target: Unused right now
        :return:
        """
        acme = AcmeDnsHandler()
        acme.cleanup_dns_challenges(acme_client, authorizations)
