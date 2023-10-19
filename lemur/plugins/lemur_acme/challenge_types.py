"""
.. module: lemur.plugins.lemur_acme.plugin
    :platform: Unix
    :synopsis: This module contains the different challenge types for ACME implementations
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Mathias Petermann <mathias.petermann@projektfokus.ch>
"""
from datetime import datetime, timedelta
import json

from acme import challenges
from acme.errors import WildcardUnsupportedError
from acme.messages import errors, STATUS_VALID, ERROR_CODES
from botocore.exceptions import ClientError
from flask import current_app
from sentry_sdk import capture_exception

from lemur.authorizations import service as authorization_service
from lemur.constants import ACME_ADDITIONAL_ATTEMPTS
from lemur.common.utils import drop_last_cert_from_chain
from lemur.exceptions import LemurException, InvalidConfiguration
from lemur.extensions import metrics
from lemur.plugins.base import plugins
from lemur.destinations import service as destination_service
from lemur.plugins.lemur_acme.acme_handlers import AcmeHandler, AcmeDnsHandler

from retrying import retry


class AcmeChallengeMissmatchError(LemurException):
    pass


class AcmeChallenge:
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
        deployed_challenges = []
        all_pre_validated = True
        for authz in orderr.authorizations:
            # Choosing challenge.
            if authz.body.status != STATUS_VALID:
                all_pre_validated = False
                # authz.body.challenges is a set of ChallengeBody objects.
                for i in authz.body.challenges:
                    # Find the supported challenge.
                    if isinstance(i.chall, challenges.HTTP01):
                        chall.append(i)
            else:
                metrics.send("get_acme_challenges_already_valid", "counter", 1)
                log_data = {"message": "already validated, skipping", "hostname": authz.body.identifier.value}
                current_app.logger.info(log_data)

        if len(chall) == 0 and not all_pre_validated:
            raise Exception(f'HTTP-01 challenge was not offered by the CA server at {orderr.uri}')
        elif not all_pre_validated:
            validation_target = None
            for option in json.loads(issuer_options["authority"].options):
                if option["name"] == "tokenDestination":
                    validation_target = option["value"]

            if validation_target is None:
                raise Exception('No token_destination configured for this authority. Cant complete HTTP-01 challenge')

            for challenge in chall:
                try:
                    response = self.deploy(challenge, acme_client, validation_target)
                    deployed_challenges.append(challenge.chall.path)
                    acme_client.answer_challenge(challenge, response)
                except Exception as e:
                    current_app.logger.error(e)
                    raise Exception('Failure while trying to deploy token to configure destination. See logs for more information')

            current_app.logger.info("Uploaded HTTP-01 challenge tokens, trying to poll and finalize the order")

        try:
            deadline = datetime.now() + timedelta(seconds=90)
            orderr = acme_client.poll_authorizations(orderr, deadline)
            finalized_orderr = acme_client.finalize_order(orderr, deadline, fetch_alternative_chains=True)

        except errors.ValidationError as validationError:
            error_message = "Validation error occurred, can\'t complete challenges. See logs for more information."
            for authz in validationError.failed_authzrs:
                for chall in authz.body.challenges:
                    if chall.error:
                        error_message = f"ValidationError occurred of type: {chall.error.typ}, " \
                                        f"with message: {ERROR_CODES[chall.error.code]}, " \
                                        f"detail: {chall.error.detail}"
                        current_app.logger.error(error_message)

            raise Exception(error_message)

        pem_certificate, pem_certificate_chain = self.acme.extract_cert_and_chain(finalized_orderr.fullchain_pem,
                                                                                  finalized_orderr.alternative_fullchains_pem)

        if "drop_last_cert_from_chain" in authority.options:
            for option in json.loads(authority.options):
                if option["name"] == "drop_last_cert_from_chain" and option["value"] is True:
                    # skipping the last element
                    pem_certificate_chain = drop_last_cert_from_chain(pem_certificate_chain)

        self.acme.log_remaining_validation(finalized_orderr.authorizations,
                                           acme_client.net.account.uri.replace('https://', ''))

        if len(deployed_challenges) != 0:
            for token_path in deployed_challenges:
                self.cleanup(token_path, validation_target)

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
                f'Couldn\'t find the destination with name {validation_target}. Cant complete HTTP01 challenge')

        destination_plugin = plugins.get(destination.plugin_name)

        response, validation = challenge.response_and_validation(acme_client.net.key)

        destination_plugin.upload_acme_token(challenge.chall.path, validation, destination.options)
        current_app.logger.info("Uploaded HTTP-01 challenge token.")

        return response

    def cleanup(self, token_path, validation_target):
        destination = destination_service.get(validation_target)

        if destination is None:
            current_app.logger.info(
                f'Couldn\'t find the destination with name {validation_target}, won\'t cleanup the challenge')

        destination_plugin = plugins.get(destination.plugin_name)

        destination_plugin.delete_acme_token(token_path, destination.options)
        current_app.logger.info("Cleaned up HTTP-01 challenge token.")


class AcmeDnsChallenge(AcmeChallenge):
    challengeType = challenges.DNS01

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
        domains = self.acme.get_domains(issuer_options)
        dns_provider = issuer_options.get("dns_provider", {})

        if dns_provider:
            for domain in domains:
                # Currently, we only support specifying one DNS provider per certificate, even if that
                # certificate has multiple SANs that may belong to different provid
                self.acme.dns_providers_for_domain[domain] = [dns_provider]

            credentials = json.loads(dns_provider.credentials)
            current_app.logger.debug(
                f"Using DNS provider: {dns_provider.provider_type}"
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
            account_number = None
            provider_type = None

            for domain in domains:
                self.acme.autodetect_dns_providers(domain)

        # Create pending authorizations that we'll need to do the creation
        dns_authorization = authorization_service.create(
            account_number, domains, provider_type
        )

        if not create_immediately:
            # Return id of the DNS Authorization
            return None, None, dns_authorization.id

        pem_certificate, pem_certificate_chain = self.create_certificate_immediately(
            acme_client, dns_authorization, csr
        )

        if "drop_last_cert_from_chain" in authority.options \
                and authority.options.get("drop_last_cert_from_chain") is True:
            # skipping the last element
            pem_certificate_chain = drop_last_cert_from_chain(pem_certificate_chain)

        # TODO add external ID (if possible)
        return pem_certificate, pem_certificate_chain, None

    @retry(stop_max_attempt_number=ACME_ADDITIONAL_ATTEMPTS, wait_fixed=5000)
    def create_certificate_immediately(self, acme_client, order_info, csr):
        try:
            order = acme_client.new_order(csr)
        except WildcardUnsupportedError:
            metrics.send("create_certificte_immediately_wildcard_unsupported", "counter", 1)
            raise Exception(
                "The currently selected ACME CA endpoint does"
                " not support issuing wildcard certificates."
            )

        try:
            authorizations = self.acme.get_authorizations(
                acme_client, order, order_info
            )
        except ClientError:
            capture_exception()
            metrics.send("create_certificate_immediately_error", "counter", 1)

            current_app.logger.error(
                f"Unable to resolve cert for domains: {', '.join(order_info.domains)}", exc_info=True
            )
            return False

        authorizations = self.acme.finalize_authorizations(acme_client, authorizations)

        return self.acme.request_certificate(
            acme_client, authorizations, order
        )

    def deploy(self, challenge, acme_client, validation_target):
        pass

    def cleanup(self, authorizations, acme_client, validation_target=None):
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
