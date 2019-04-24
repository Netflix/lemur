"""
.. module: lemur.plugins.lemur_acme.plugin
    :platform: Unix
    :synopsis: This module is responsible for communicating with an ACME CA.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Snippets from https://raw.githubusercontent.com/alex/letsencrypt-aws/master/letsencrypt-aws.py

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
.. moduleauthor:: Curtis Castrapel <ccastrapel@netflix.com>
"""
import datetime
import json
import time

import OpenSSL.crypto
import josepy as jose
from acme import challenges, messages
from acme.client import BackwardsCompatibleClientV2, ClientNetwork
from acme.errors import PollError, WildcardUnsupportedError
from acme.messages import Error as AcmeError
from botocore.exceptions import ClientError
from flask import current_app

from lemur.authorizations import service as authorization_service
from lemur.common.utils import generate_private_key
from lemur.dns_providers import service as dns_provider_service
from lemur.exceptions import InvalidAuthority, InvalidConfiguration, UnknownProvider
from lemur.extensions import metrics, sentry
from lemur.plugins import lemur_acme as acme
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins.lemur_acme import cloudflare, dyn, route53


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


class AcmeHandler(object):
    def __init__(self):
        self.dns_providers_for_domain = {}
        try:
            self.all_dns_providers = dns_provider_service.get_all_dns_providers()
        except Exception as e:
            metrics.send('AcmeHandler_init_error', 'counter', 1)
            sentry.captureException()
            current_app.logger.error(f"Unable to fetch DNS Providers: {e}")
            self.all_dns_providers = []

    def find_dns_challenge(self, authorizations):
        dns_challenges = []
        for authz in authorizations:
            for combo in authz.body.challenges:
                if isinstance(combo.chall, challenges.DNS01):
                    dns_challenges.append(combo)
        return dns_challenges

    def maybe_remove_wildcard(self, host):
        return host.replace("*.", "")

    def maybe_add_extension(self, host, dns_provider_options):
        if dns_provider_options and dns_provider_options.get("acme_challenge_extension"):
            host = host + dns_provider_options.get("acme_challenge_extension")
        return host

    def start_dns_challenge(self, acme_client, account_number, host, dns_provider, order, dns_provider_options):
        current_app.logger.debug("Starting DNS challenge for {0}".format(host))

        dns_challenges = self.find_dns_challenge(order.authorizations)
        change_ids = []

        host_to_validate = self.maybe_remove_wildcard(host)
        host_to_validate = self.maybe_add_extension(host_to_validate, dns_provider_options)

        for dns_challenge in self.find_dns_challenge(order.authorizations):
            change_id = dns_provider.create_txt_record(
                dns_challenge.validation_domain_name(host_to_validate),
                dns_challenge.validation(acme_client.client.net.key),
                account_number
            )
            change_ids.append(change_id)

        return AuthorizationRecord(
            host,
            order.authorizations,
            dns_challenges,
            change_ids
        )

    def complete_dns_challenge(self, acme_client, authz_record):
        current_app.logger.debug("Finalizing DNS challenge for {0}".format(authz_record.authz[0].body.identifier.value))
        dns_providers = self.dns_providers_for_domain.get(authz_record.host)
        if not dns_providers:
            metrics.send('complete_dns_challenge_error_no_dnsproviders', 'counter', 1)
            raise Exception("No DNS providers found for domain: {}".format(authz_record.host))

        for dns_provider in dns_providers:
            # Grab account number (For Route53)
            dns_provider_options = json.loads(dns_provider.credentials)
            account_number = dns_provider_options.get("account_id")
            dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
            for change_id in authz_record.change_id:
                try:
                    dns_provider_plugin.wait_for_dns_change(change_id, account_number=account_number)
                except Exception:
                    metrics.send('complete_dns_challenge_error', 'counter', 1)
                    sentry.captureException()
                    current_app.logger.debug(
                        f"Unable to resolve DNS challenge for change_id: {change_id}, account_id: "
                        f"{account_number}", exc_info=True)
                    raise

            for dns_challenge in authz_record.dns_challenge:
                response = dns_challenge.response(acme_client.client.net.key)

                verified = response.simple_verify(
                    dns_challenge.chall,
                    authz_record.host,
                    acme_client.client.net.key.public_key()
                )

                if not verified:
                    metrics.send('complete_dns_challenge_verification_error', 'counter', 1)
                    raise ValueError("Failed verification")

                time.sleep(5)
                acme_client.answer_challenge(dns_challenge, response)

    def request_certificate(self, acme_client, authorizations, order):
        for authorization in authorizations:
            for authz in authorization.authz:
                authorization_resource, _ = acme_client.poll(authz)

        deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)

        try:
            orderr = acme_client.finalize_order(order, deadline)
        except AcmeError:
            sentry.captureException()
            metrics.send('request_certificate_error', 'counter', 1)
            current_app.logger.error(f"Unable to resolve Acme order: {order}", exc_info=True)
            raise

        pem_certificate = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                          OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                                                                          orderr.fullchain_pem)).decode()
        pem_certificate_chain = orderr.fullchain_pem[len(pem_certificate):].lstrip()

        current_app.logger.debug("{0} {1}".format(type(pem_certificate), type(pem_certificate_chain)))
        return pem_certificate, pem_certificate_chain

    def setup_acme_client(self, authority):
        if not authority.options:
            raise InvalidAuthority("Invalid authority. Options not set")
        options = {}

        for option in json.loads(authority.options):
            options[option["name"]] = option.get("value")
        email = options.get('email', current_app.config.get('ACME_EMAIL'))
        tel = options.get('telephone', current_app.config.get('ACME_TEL'))
        directory_url = options.get('acme_url', current_app.config.get('ACME_DIRECTORY_URL'))

        existing_key = options.get('acme_private_key', current_app.config.get('ACME_PRIVATE_KEY'))
        existing_regr = options.get('acme_regr', current_app.config.get('ACME_REGR'))

        if existing_key and existing_regr:
            # Reuse the same account for each certificate issuance
            key = jose.JWK.json_loads(existing_key)
            regr = messages.RegistrationResource.json_loads(existing_regr)
            current_app.logger.debug("Connecting with directory at {0}".format(directory_url))
            net = ClientNetwork(key, account=regr)
            client = BackwardsCompatibleClientV2(net, key, directory_url)
            return client, {}
        else:
            # Create an account for each certificate issuance
            key = jose.JWKRSA(key=generate_private_key('RSA2048'))

            current_app.logger.debug("Connecting with directory at {0}".format(directory_url))

            net = ClientNetwork(key, account=None, timeout=3600)
            client = BackwardsCompatibleClientV2(net, key, directory_url)
            registration = client.new_account_and_tos(messages.NewRegistration.from_data(email=email))
            current_app.logger.debug("Connected: {0}".format(registration.uri))

        return client, registration

    def get_domains(self, options):
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

    def get_authorizations(self, acme_client, order, order_info):
        authorizations = []

        for domain in order_info.domains:
            if not self.dns_providers_for_domain.get(domain):
                metrics.send('get_authorizations_no_dns_provider_for_domain', 'counter', 1)
                raise Exception("No DNS providers found for domain: {}".format(domain))
            for dns_provider in self.dns_providers_for_domain[domain]:
                dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
                dns_provider_options = json.loads(dns_provider.credentials)
                account_number = dns_provider_options.get("account_id")
                authz_record = self.start_dns_challenge(acme_client, account_number, domain,
                                                        dns_provider_plugin,
                                                        order,
                                                        dns_provider.options)
                authorizations.append(authz_record)
        return authorizations

    def autodetect_dns_providers(self, domain):
        """
        Get DNS providers associated with a domain when it has not been provided for certificate creation.
        :param domain:
        :return: dns_providers: List of DNS providers that have the correct zone.
        """
        self.dns_providers_for_domain[domain] = []
        match_length = 0
        for dns_provider in self.all_dns_providers:
            if not dns_provider.domains:
                continue
            for name in dns_provider.domains:
                if domain.endswith("." + name):
                    if len(name) > match_length:
                        self.dns_providers_for_domain[domain] = [dns_provider]
                        match_length = len(name)
                    elif len(name) == match_length:
                        self.dns_providers_for_domain[domain].append(dns_provider)

        return self.dns_providers_for_domain

    def finalize_authorizations(self, acme_client, authorizations):
        for authz_record in authorizations:
            self.complete_dns_challenge(acme_client, authz_record)
        for authz_record in authorizations:
            dns_challenges = authz_record.dns_challenge
            for dns_challenge in dns_challenges:
                dns_providers = self.dns_providers_for_domain.get(authz_record.host)
                for dns_provider in dns_providers:
                    # Grab account number (For Route53)
                    dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
                    dns_provider_options = json.loads(dns_provider.credentials)
                    account_number = dns_provider_options.get("account_id")
                    host_to_validate = self.maybe_remove_wildcard(authz_record.host)
                    host_to_validate = self.maybe_add_extension(host_to_validate, dns_provider_options)
                    dns_provider_plugin.delete_txt_record(
                        authz_record.change_id,
                        account_number,
                        dns_challenge.validation_domain_name(host_to_validate),
                        dns_challenge.validation(acme_client.client.net.key)
                    )

        return authorizations

    def cleanup_dns_challenges(self, acme_client, authorizations):
        """
        Best effort attempt to delete DNS challenges that may not have been deleted previously. This is usually called
        on an exception

        :param acme_client:
        :param account_number:
        :param dns_provider:
        :param authorizations:
        :param dns_provider_options:
        :return:
        """
        for authz_record in authorizations:
            dns_providers = self.dns_providers_for_domain.get(authz_record.host)
            for dns_provider in dns_providers:
                # Grab account number (For Route53)
                dns_provider_options = json.loads(dns_provider.credentials)
                account_number = dns_provider_options.get("account_id")
                dns_challenges = authz_record.dns_challenge
                host_to_validate = self.maybe_remove_wildcard(authz_record.host)
                host_to_validate = self.maybe_add_extension(host_to_validate, dns_provider_options)
                for dns_challenge in dns_challenges:
                    try:
                        dns_provider.delete_txt_record(
                            authz_record.change_id,
                            account_number,
                            dns_challenge.validation_domain_name(host_to_validate),
                            dns_challenge.validation(acme_client.client.net.key)
                        )
                    except Exception as e:
                        # If this fails, it's most likely because the record doesn't exist (It was already cleaned up)
                        # or we're not authorized to modify it.
                        metrics.send('cleanup_dns_challenges_error', 'counter', 1)
                        sentry.captureException()
                        pass

    def get_dns_provider(self, type):
        provider_types = {
            'cloudflare': cloudflare,
            'dyn': dyn,
            'route53': route53,
        }
        provider = provider_types.get(type)
        if not provider:
            raise UnknownProvider("No such DNS provider: {}".format(type))
        return provider


class ACMEIssuerPlugin(IssuerPlugin):
    title = 'Acme'
    slug = 'acme-issuer'
    description = 'Enables the creation of certificates via ACME CAs (including Let\'s Encrypt)'
    version = acme.VERSION

    author = 'Netflix'
    author_url = 'https://github.com/netflix/lemur.git'

    options = [
        {
            'name': 'acme_url',
            'type': 'str',
            'required': True,
            'validation': '/^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$/',
            'helpMessage': 'Must be a valid web url starting with http[s]://',
        },
        {
            'name': 'telephone',
            'type': 'str',
            'default': '',
            'helpMessage': 'Telephone to use'
        },
        {
            'name': 'email',
            'type': 'str',
            'default': '',
            'validation': '/^?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)$/',
            'helpMessage': 'Email to use'
        },
        {
            'name': 'certificate',
            'type': 'textarea',
            'default': '',
            'validation': '/^-----BEGIN CERTIFICATE-----/',
            'helpMessage': 'Certificate to use'
        },
    ]

    def __init__(self, *args, **kwargs):
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    def get_dns_provider(self, type):
        self.acme = AcmeHandler()

        provider_types = {
            'cloudflare': cloudflare,
            'dyn': dyn,
            'route53': route53,
        }
        provider = provider_types.get(type)
        if not provider:
            raise UnknownProvider("No such DNS provider: {}".format(type))
        return provider

    def get_all_zones(self, dns_provider):
        self.acme = AcmeHandler()
        dns_provider_options = json.loads(dns_provider.credentials)
        account_number = dns_provider_options.get("account_id")
        dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
        return dns_provider_plugin.get_zones(account_number=account_number)

    def get_ordered_certificate(self, pending_cert):
        self.acme = AcmeHandler()
        acme_client, registration = self.acme.setup_acme_client(pending_cert.authority)
        order_info = authorization_service.get(pending_cert.external_id)
        if pending_cert.dns_provider_id:
            dns_provider = dns_provider_service.get(pending_cert.dns_provider_id)

            for domain in order_info.domains:
                # Currently, we only support specifying one DNS provider per certificate, even if that
                # certificate has multiple SANs that may belong to different providers.
                self.acme.dns_providers_for_domain[domain] = [dns_provider]
        else:
            for domain in order_info.domains:
                self.acme.autodetect_dns_providers(domain)

        try:
            order = acme_client.new_order(pending_cert.csr)
        except WildcardUnsupportedError:
            metrics.send('get_ordered_certificate_wildcard_unsupported', 'counter', 1)
            raise Exception("The currently selected ACME CA endpoint does"
                            " not support issuing wildcard certificates.")
        try:
            authorizations = self.acme.get_authorizations(acme_client, order, order_info)
        except ClientError:
            sentry.captureException()
            metrics.send('get_ordered_certificate_error', 'counter', 1)
            current_app.logger.error(f"Unable to resolve pending cert: {pending_cert.name}", exc_info=True)
            return False

        authorizations = self.acme.finalize_authorizations(acme_client, authorizations)
        pem_certificate, pem_certificate_chain = self.acme.request_certificate(
            acme_client, authorizations, order)
        cert = {
            'body': "\n".join(str(pem_certificate).splitlines()),
            'chain': "\n".join(str(pem_certificate_chain).splitlines()),
            'external_id': str(pending_cert.external_id)
        }
        return cert

    def get_ordered_certificates(self, pending_certs):
        self.acme = AcmeHandler()
        pending = []
        certs = []
        for pending_cert in pending_certs:
            try:
                acme_client, registration = self.acme.setup_acme_client(pending_cert.authority)
                order_info = authorization_service.get(pending_cert.external_id)
                if pending_cert.dns_provider_id:
                    dns_provider = dns_provider_service.get(pending_cert.dns_provider_id)

                    for domain in order_info.domains:
                        # Currently, we only support specifying one DNS provider per certificate, even if that
                        # certificate has multiple SANs that may belong to different providers.
                        self.acme.dns_providers_for_domain[domain] = [dns_provider]
                else:
                    for domain in order_info.domains:
                        self.acme.autodetect_dns_providers(domain)

                try:
                    order = acme_client.new_order(pending_cert.csr)
                except WildcardUnsupportedError:
                    sentry.captureException()
                    metrics.send('get_ordered_certificates_wildcard_unsupported_error', 'counter', 1)
                    raise Exception("The currently selected ACME CA endpoint does"
                                    " not support issuing wildcard certificates.")

                authorizations = self.acme.get_authorizations(acme_client, order, order_info)

                pending.append({
                    "acme_client": acme_client,
                    "authorizations": authorizations,
                    "pending_cert": pending_cert,
                    "order": order,
                })
            except (ClientError, ValueError, Exception) as e:
                sentry.captureException()
                metrics.send('get_ordered_certificates_pending_creation_error', 'counter', 1)
                current_app.logger.error(f"Unable to resolve pending cert: {pending_cert}", exc_info=True)

                error = e
                if globals().get("order") and order:
                    error += f" Order uri: {order.uri}"
                certs.append({
                    "cert": False,
                    "pending_cert": pending_cert,
                    "last_error": e,
                })

        for entry in pending:
            try:
                entry["authorizations"] = self.acme.finalize_authorizations(
                    entry["acme_client"],
                    entry["authorizations"],
                )
                pem_certificate, pem_certificate_chain = self.acme.request_certificate(
                    entry["acme_client"],
                    entry["authorizations"],
                    entry["order"]
                )

                cert = {
                    'body': "\n".join(str(pem_certificate).splitlines()),
                    'chain': "\n".join(str(pem_certificate_chain).splitlines()),
                    'external_id': str(entry["pending_cert"].external_id)
                }
                certs.append({
                    "cert": cert,
                    "pending_cert": entry["pending_cert"],
                })
            except (PollError, AcmeError, Exception) as e:
                sentry.captureException()
                metrics.send('get_ordered_certificates_resolution_error', 'counter', 1)
                order_url = order.uri
                error = f"{e}. Order URI: {order_url}"
                current_app.logger.error(
                    f"Unable to resolve pending cert: {pending_cert}. "
                    f"Check out {order_url} for more information.", exc_info=True)
                certs.append({
                    "cert": False,
                    "pending_cert": entry["pending_cert"],
                    "last_error": error,
                })
                # Ensure DNS records get deleted
                self.acme.cleanup_dns_challenges(
                    entry["acme_client"],
                    entry["authorizations"],
                )
        return certs

    def create_certificate(self, csr, issuer_options):
        """
        Creates an ACME certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        self.acme = AcmeHandler()
        authority = issuer_options.get('authority')
        create_immediately = issuer_options.get('create_immediately', False)
        acme_client, registration = self.acme.setup_acme_client(authority)
        dns_provider = issuer_options.get('dns_provider', {})

        if dns_provider:
            dns_provider_options = dns_provider.options
            credentials = json.loads(dns_provider.credentials)
            current_app.logger.debug("Using DNS provider: {0}".format(dns_provider.provider_type))
            dns_provider_plugin = __import__(dns_provider.provider_type, globals(), locals(), [], 1)
            account_number = credentials.get("account_id")
            provider_type = dns_provider.provider_type
            if provider_type == "route53" and not account_number:
                error = "Route53 DNS Provider {} does not have an account number configured.".format(dns_provider.name)
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
            authz_domains = []
            for d in domains:
                if type(d) == str:
                    authz_domains.append(d)
                else:
                    authz_domains.append(d.value)

            dns_authorization = authorization_service.create(account_number, authz_domains,
                                                             provider_type)
            # Return id of the DNS Authorization
            return None, None, dns_authorization.id

        authorizations = self.acme.get_authorizations(acme_client, account_number, domains, dns_provider_plugin,
                                                      dns_provider_options)
        self.acme.finalize_authorizations(acme_client, account_number, dns_provider_plugin, authorizations,
                                          dns_provider_options)
        pem_certificate, pem_certificate_chain = self.acme.request_certificate(acme_client, authorizations, csr)
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
        plugin_options = options.get('plugin', {}).get('plugin_options')
        if not plugin_options:
            error = "Invalid options for lemur_acme plugin: {}".format(options)
            current_app.logger.error(error)
            raise InvalidConfiguration(error)
        # Define static acme_root based off configuration variable by default. However, if user has passed a
        # certificate, use this certificate as the root.
        acme_root = current_app.config.get('ACME_ROOT')
        for option in plugin_options:
            if option.get('name') == 'certificate':
                acme_root = option.get('value')
        return acme_root, "", [role]

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        # Needed to override issuer function.
        pass
