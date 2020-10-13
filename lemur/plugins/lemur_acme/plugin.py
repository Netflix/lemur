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
from acme import challenges, errors, messages
from acme.client import BackwardsCompatibleClientV2, ClientNetwork
from acme.errors import PollError, TimeoutError, WildcardUnsupportedError
from acme.messages import Error as AcmeError
from botocore.exceptions import ClientError
from flask import current_app

from lemur.authorizations import service as authorization_service
from lemur.common.utils import generate_private_key
from lemur.destinations import service as destination_service
from lemur.dns_providers import service as dns_provider_service
from lemur.exceptions import InvalidAuthority, InvalidConfiguration, UnknownProvider
from lemur.extensions import metrics, sentry

from lemur.plugins.base import plugins
from lemur.plugins import lemur_acme as acme
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins.lemur_acme import cloudflare, dyn, route53, ultradns, powerdns
from lemur.authorities import service as authorities_service
from retrying import retry


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


class AcmeHandler(object):

    def reuse_account(self, authority):
        if not authority.options:
            raise InvalidAuthority("Invalid authority. Options not set")
        existing_key = False
        existing_regr = False

        for option in json.loads(authority.options):
            if option["name"] == "acme_private_key" and option["value"]:
                existing_key = True
            if option["name"] == "acme_regr" and option["value"]:
                existing_regr = True

        if not existing_key and current_app.config.get("ACME_PRIVATE_KEY"):
            existing_key = True

        if not existing_regr and current_app.config.get("ACME_REGR"):
            existing_regr = True

        if existing_key and existing_regr:
            return True
        else:
            return False

    def strip_wildcard(self, host):
        """Removes the leading *. and returns Host and whether it was removed or not (True/False)"""
        prefix = "*."
        if host.startswith(prefix):
            return host[len(prefix):], True
        return host, False

    def maybe_add_extension(self, host, dns_provider_options):
        if dns_provider_options and dns_provider_options.get(
                "acme_challenge_extension"
        ):
            host = host + dns_provider_options.get("acme_challenge_extension")
        return host

    def request_certificate(self, acme_client, authorizations, order):
        for authorization in authorizations:
            for authz in authorization.authz:
                authorization_resource, _ = acme_client.poll(authz)

        deadline = datetime.datetime.now() + datetime.timedelta(seconds=360)

        try:
            orderr = acme_client.poll_and_finalize(order, deadline)

        except (AcmeError, TimeoutError):
            sentry.captureException(extra={"order_url": str(order.uri)})
            metrics.send("request_certificate_error", "counter", 1, metric_tags={"uri": order.uri})
            current_app.logger.error(
                f"Unable to resolve Acme order: {order.uri}", exc_info=True
            )
            raise
        except errors.ValidationError:
            if order.fullchain_pem:
                orderr = order
            else:
                raise

        metrics.send("request_certificate_success", "counter", 1, metric_tags={"uri": order.uri})
        current_app.logger.info(
            f"Successfully resolved Acme order: {order.uri}", exc_info=True
        )

        pem_certificate = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, orderr.fullchain_pem
            ),
        ).decode()

        if current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA", False) \
                and datetime.datetime.now() < datetime.datetime.strptime(
                current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA_EXPIRATION_DATE", "17/03/21"), '%d/%m/%y'):
            pem_certificate_chain = current_app.config.get("IDENTRUST_CROSS_SIGNED_LE_ICA")
        else:
            pem_certificate_chain = orderr.fullchain_pem[
                                    len(pem_certificate):  # noqa
                                    ].lstrip()

        current_app.logger.debug(
            "{0} {1}".format(type(pem_certificate), type(pem_certificate_chain))
        )
        return pem_certificate, pem_certificate_chain

    @retry(stop_max_attempt_number=5, wait_fixed=5000)
    def setup_acme_client(self, authority):
        if not authority.options:
            raise InvalidAuthority("Invalid authority. Options not set")
        options = {}

        for option in json.loads(authority.options):
            options[option["name"]] = option.get("value")
        email = options.get("email", current_app.config.get("ACME_EMAIL"))
        tel = options.get("telephone", current_app.config.get("ACME_TEL"))
        directory_url = options.get(
            "acme_url", current_app.config.get("ACME_DIRECTORY_URL")
        )

        existing_key = options.get(
            "acme_private_key", current_app.config.get("ACME_PRIVATE_KEY")
        )
        existing_regr = options.get("acme_regr", current_app.config.get("ACME_REGR"))

        if existing_key and existing_regr:
            current_app.logger.debug("Reusing existing ACME account")
            # Reuse the same account for each certificate issuance
            key = jose.JWK.json_loads(existing_key)
            regr = messages.RegistrationResource.json_loads(existing_regr)
            current_app.logger.debug(
                "Connecting with directory at {0}".format(directory_url)
            )
            net = ClientNetwork(key, account=regr)
            client = BackwardsCompatibleClientV2(net, key, directory_url)
            return client, {}
        else:
            # Create an account for each certificate issuance
            key = jose.JWKRSA(key=generate_private_key("RSA2048"))

            current_app.logger.debug("Creating a new ACME account")
            current_app.logger.debug(
                "Connecting with directory at {0}".format(directory_url)
            )

            net = ClientNetwork(key, account=None, timeout=3600)
            client = BackwardsCompatibleClientV2(net, key, directory_url)
            registration = client.new_account_and_tos(
                messages.NewRegistration.from_data(email=email)
            )

            # if store_account is checked, add the private_key and registration resources to the options
            if options['store_account']:
                new_options = json.loads(authority.options)
                # the key returned by fields_to_partial_json is missing the key type, so we add it manually
                key_dict = key.fields_to_partial_json()
                key_dict["kty"] = "RSA"
                acme_private_key = {
                    "name": "acme_private_key",
                    "value": json.dumps(key_dict)
                }
                new_options.append(acme_private_key)

                acme_regr = {
                    "name": "acme_regr",
                    "value": json.dumps({"body": {}, "uri": registration.uri})
                }
                new_options.append(acme_regr)

                authorities_service.update_options(authority.id, options=json.dumps(new_options))

            current_app.logger.debug("Connected: {0}".format(registration.uri))

        return client, registration

    def get_domains(self, options):
        """
        Fetches all domains currently requested
        :param options:
        :return:
        """
        current_app.logger.debug("Fetching domains")

        domains = [options["common_name"]]
        if options.get("extensions"):
            for dns_name in options["extensions"]["sub_alt_names"]["names"]:
                if dns_name.value not in domains:
                    domains.append(dns_name.value)

        current_app.logger.debug("Got these domains: {0}".format(domains))
        return domains


class AcmeDnsHandler(AcmeHandler):

    def __init__(self):
        self.dns_providers_for_domain = {}
        try:
            self.all_dns_providers = dns_provider_service.get_all_dns_providers()
        except Exception as e:
            metrics.send("AcmeHandler_init_error", "counter", 1)
            sentry.captureException()
            current_app.logger.error(f"Unable to fetch DNS Providers: {e}")
            self.all_dns_providers = []

    def get_dns_challenges(self, host, authorizations):
        """Get dns challenges for provided domain"""

        domain_to_validate, is_wildcard = self.strip_wildcard(host)
        dns_challenges = []
        for authz in authorizations:
            if not authz.body.identifier.value.lower() == domain_to_validate.lower():
                continue
            if is_wildcard and not authz.body.wildcard:
                continue
            if not is_wildcard and authz.body.wildcard:
                continue
            for combo in authz.body.challenges:
                if isinstance(combo.chall, challenges.DNS01):
                    dns_challenges.append(combo)

        return dns_challenges

    def get_dns_provider(self, type):
        provider_types = {
            "cloudflare": cloudflare,
            "dyn": dyn,
            "route53": route53,
            "ultradns": ultradns,
            "powerdns": powerdns
        }
        provider = provider_types.get(type)
        if not provider:
            raise UnknownProvider("No such DNS provider: {}".format(type))
        return provider

    def start_dns_challenge(
            self,
            acme_client,
            account_number,
            host,
            dns_provider,
            order,
            dns_provider_options,
    ):
        current_app.logger.debug("Starting DNS challenge for {0}".format(host))

        change_ids = []
        dns_challenges = self.get_dns_challenges(host, order.authorizations)
        host_to_validate, _ = self.strip_wildcard(host)
        host_to_validate = self.maybe_add_extension(
            host_to_validate, dns_provider_options
        )

        if not dns_challenges:
            sentry.captureException()
            metrics.send("start_dns_challenge_error_no_dns_challenges", "counter", 1)
            raise Exception("Unable to determine DNS challenges from authorizations")

        for dns_challenge in dns_challenges:
            change_id = dns_provider.create_txt_record(
                dns_challenge.validation_domain_name(host_to_validate),
                dns_challenge.validation(acme_client.client.net.key),
                account_number,
            )
            change_ids.append(change_id)

        return AuthorizationRecord(
            host, order.authorizations, dns_challenges, change_ids
        )

    def complete_dns_challenge(self, acme_client, authz_record):
        current_app.logger.debug(
            "Finalizing DNS challenge for {0}".format(
                authz_record.authz[0].body.identifier.value
            )
        )
        dns_providers = self.dns_providers_for_domain.get(authz_record.host)
        if not dns_providers:
            metrics.send("complete_dns_challenge_error_no_dnsproviders", "counter", 1)
            raise Exception(
                "No DNS providers found for domain: {}".format(authz_record.host)
            )

        for dns_provider in dns_providers:
            # Grab account number (For Route53)
            dns_provider_options = json.loads(dns_provider.credentials)
            account_number = dns_provider_options.get("account_id")
            dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
            for change_id in authz_record.change_id:
                try:
                    dns_provider_plugin.wait_for_dns_change(
                        change_id, account_number=account_number
                    )
                except Exception:
                    metrics.send("complete_dns_challenge_error", "counter", 1)
                    sentry.captureException()
                    current_app.logger.debug(
                        f"Unable to resolve DNS challenge for change_id: {change_id}, account_id: "
                        f"{account_number}",
                        exc_info=True,
                    )
                    raise

            for dns_challenge in authz_record.dns_challenge:
                response = dns_challenge.response(acme_client.client.net.key)

                verified = response.simple_verify(
                    dns_challenge.chall,
                    authz_record.host,
                    acme_client.client.net.key.public_key(),
                )

            if not verified:
                metrics.send("complete_dns_challenge_verification_error", "counter", 1)
                raise ValueError("Failed verification")

            time.sleep(5)
            res = acme_client.answer_challenge(dns_challenge, response)
            current_app.logger.debug(f"answer_challenge response: {res}")

    def get_authorizations(self, acme_client, order, order_info):
        authorizations = []

        for domain in order_info.domains:
            if not self.dns_providers_for_domain.get(domain):
                metrics.send(
                    "get_authorizations_no_dns_provider_for_domain", "counter", 1
                )
                raise Exception("No DNS providers found for domain: {}".format(domain))
            for dns_provider in self.dns_providers_for_domain[domain]:
                dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
                dns_provider_options = json.loads(dns_provider.credentials)
                account_number = dns_provider_options.get("account_id")
                authz_record = self.start_dns_challenge(
                    acme_client,
                    account_number,
                    domain,
                    dns_provider_plugin,
                    order,
                    dns_provider.options,
                )
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
                if name == domain or domain.endswith("." + name):
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
                    dns_provider_plugin = self.get_dns_provider(
                        dns_provider.provider_type
                    )
                    dns_provider_options = json.loads(dns_provider.credentials)
                    account_number = dns_provider_options.get("account_id")
                    host_to_validate, _ = self.strip_wildcard(authz_record.host)
                    host_to_validate = self.maybe_add_extension(
                        host_to_validate, dns_provider_options
                    )
                    dns_provider_plugin.delete_txt_record(
                        authz_record.change_id,
                        account_number,
                        dns_challenge.validation_domain_name(host_to_validate),
                        dns_challenge.validation(acme_client.client.net.key),
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
                host_to_validate, _ = self.strip_wildcard(authz_record.host)
                host_to_validate = self.maybe_add_extension(
                    host_to_validate, dns_provider_options
                )
                dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
                for dns_challenge in dns_challenges:
                    try:
                        dns_provider_plugin.delete_txt_record(
                            authz_record.change_id,
                            account_number,
                            dns_challenge.validation_domain_name(host_to_validate),
                            dns_challenge.validation(acme_client.client.net.key),
                        )
                    except Exception as e:
                        # If this fails, it's most likely because the record doesn't exist (It was already cleaned up)
                        # or we're not authorized to modify it.
                        metrics.send("cleanup_dns_challenges_error", "counter", 1)
                        sentry.captureException()
                        pass


class ACMEIssuerPlugin(IssuerPlugin):
    title = "Acme"
    slug = "acme-issuer"
    description = (
        "Enables the creation of certificates via ACME CAs (including Let's Encrypt), using the DNS-01 challenge"
    )
    version = acme.VERSION

    author = "Netflix"
    author_url = "https://github.com/netflix/lemur.git"

    options = [
        {
            "name": "acme_url",
            "type": "str",
            "required": True,
            "validation": "/^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$/",
            "helpMessage": "Must be a valid web url starting with http[s]://",
        },
        {
            "name": "telephone",
            "type": "str",
            "default": "",
            "helpMessage": "Telephone to use",
        },
        {
            "name": "email",
            "type": "str",
            "default": "",
            "validation": "/^?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)$/",
            "helpMessage": "Email to use",
        },
        {
            "name": "certificate",
            "type": "textarea",
            "default": "",
            "validation": "/^-----BEGIN CERTIFICATE-----/",
            "helpMessage": "Certificate to use",
        },
        {
            "name": "store_account",
            "type": "bool",
            "required": False,
            "helpMessage": "Disable to create a new account for each ACME request",
            "default": False,
        }
    ]

    def __init__(self, *args, **kwargs):
        super(ACMEIssuerPlugin, self).__init__(*args, **kwargs)

    def get_dns_provider(self, type):
        self.acme = AcmeDnsHandler()

        provider_types = {
            "cloudflare": cloudflare,
            "dyn": dyn,
            "route53": route53,
            "ultradns": ultradns,
            "powerdns": powerdns
        }
        provider = provider_types.get(type)
        if not provider:
            raise UnknownProvider("No such DNS provider: {}".format(type))
        return provider

    def get_all_zones(self, dns_provider):
        self.acme = AcmeDnsHandler()
        dns_provider_options = json.loads(dns_provider.credentials)
        account_number = dns_provider_options.get("account_id")
        dns_provider_plugin = self.get_dns_provider(dns_provider.provider_type)
        return dns_provider_plugin.get_zones(account_number=account_number)

    def get_ordered_certificate(self, pending_cert):
        self.acme = AcmeDnsHandler()
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
            metrics.send("get_ordered_certificate_wildcard_unsupported", "counter", 1)
            raise Exception(
                "The currently selected ACME CA endpoint does"
                " not support issuing wildcard certificates."
            )
        try:
            authorizations = self.acme.get_authorizations(
                acme_client, order, order_info
            )
        except ClientError:
            sentry.captureException()
            metrics.send("get_ordered_certificate_error", "counter", 1)
            current_app.logger.error(
                f"Unable to resolve pending cert: {pending_cert.name}", exc_info=True
            )
            return False

        authorizations = self.acme.finalize_authorizations(acme_client, authorizations)
        pem_certificate, pem_certificate_chain = self.acme.request_certificate(
            acme_client, authorizations, order
        )
        cert = {
            "body": "\n".join(str(pem_certificate).splitlines()),
            "chain": "\n".join(str(pem_certificate_chain).splitlines()),
            "external_id": str(pending_cert.external_id),
        }
        return cert

    def get_ordered_certificates(self, pending_certs):
        self.acme = AcmeDnsHandler()
        pending = []
        certs = []
        for pending_cert in pending_certs:
            try:
                acme_client, registration = self.acme.setup_acme_client(
                    pending_cert.authority
                )
                order_info = authorization_service.get(pending_cert.external_id)
                if pending_cert.dns_provider_id:
                    dns_provider = dns_provider_service.get(
                        pending_cert.dns_provider_id
                    )

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
                    metrics.send(
                        "get_ordered_certificates_wildcard_unsupported_error",
                        "counter",
                        1,
                    )
                    raise Exception(
                        "The currently selected ACME CA endpoint does"
                        " not support issuing wildcard certificates."
                    )

                authorizations = self.acme.get_authorizations(
                    acme_client, order, order_info
                )

                pending.append(
                    {
                        "acme_client": acme_client,
                        "authorizations": authorizations,
                        "pending_cert": pending_cert,
                        "order": order,
                    }
                )
            except (ClientError, ValueError, Exception) as e:
                sentry.captureException()
                metrics.send(
                    "get_ordered_certificates_pending_creation_error", "counter", 1
                )
                current_app.logger.error(
                    f"Unable to resolve pending cert: {pending_cert}", exc_info=True
                )

                error = e
                if globals().get("order") and order:
                    error += f" Order uri: {order.uri}"
                certs.append(
                    {"cert": False, "pending_cert": pending_cert, "last_error": e}
                )

        for entry in pending:
            try:
                entry["authorizations"] = self.acme.finalize_authorizations(
                    entry["acme_client"], entry["authorizations"]
                )
                pem_certificate, pem_certificate_chain = self.acme.request_certificate(
                    entry["acme_client"], entry["authorizations"], entry["order"]
                )

                cert = {
                    "body": "\n".join(str(pem_certificate).splitlines()),
                    "chain": "\n".join(str(pem_certificate_chain).splitlines()),
                    "external_id": str(entry["pending_cert"].external_id),
                }
                certs.append({"cert": cert, "pending_cert": entry["pending_cert"]})
            except (PollError, AcmeError, Exception) as e:
                sentry.captureException()
                metrics.send("get_ordered_certificates_resolution_error", "counter", 1)
                order_url = order.uri
                error = f"{e}. Order URI: {order_url}"
                current_app.logger.error(
                    f"Unable to resolve pending cert: {pending_cert}. "
                    f"Check out {order_url} for more information.",
                    exc_info=True,
                )
                certs.append(
                    {
                        "cert": False,
                        "pending_cert": entry["pending_cert"],
                        "last_error": error,
                    }
                )
                # Ensure DNS records get deleted
                self.acme.cleanup_dns_challenges(
                    entry["acme_client"], entry["authorizations"]
                )
        return certs

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

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "acme"}
        plugin_options = options.get("plugin", {}).get("plugin_options")
        if not plugin_options:
            error = "Invalid options for lemur_acme plugin: {}".format(options)
            current_app.logger.error(error)
            raise InvalidConfiguration(error)
        # Define static acme_root based off configuration variable by default. However, if user has passed a
        # certificate, use this certificate as the root.
        acme_root = current_app.config.get("ACME_ROOT")
        for option in plugin_options:
            if option.get("name") == "certificate":
                acme_root = option.get("value")
        return acme_root, "", [role]

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        # Needed to override issuer function.
        pass

    def revoke_certificate(self, certificate, comments):
        self.acme = AcmeDnsHandler()
        if not self.acme.reuse_account(certificate.authority):
            raise InvalidConfiguration("There is no ACME account saved, unable to revoke the certificate.")
        acme_client, _ = self.acme.setup_acme_client(certificate.authority)

        fullchain_com = jose.ComparableX509(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, certificate.body))

        try:
            acme_client.revoke(fullchain_com, 0)  # revocation reason = 0
        except (errors.ConflictError, errors.ClientError, errors.Error) as e:
            # Certificate already revoked.
            current_app.logger.error("Certificate revocation failed with message: " + e.detail)
            metrics.send("acme_revoke_certificate_failure", "counter", 1)
            return False

        current_app.logger.warning("Certificate succesfully revoked: " + certificate.name)
        metrics.send("acme_revoke_certificate_success", "counter", 1)
        return True


class ACMEHttpIssuerPlugin(IssuerPlugin):
    title = "Acme HTTP-01"
    slug = "acme-http-issuer"
    description = (
        "Enables the creation of certificates via ACME CAs (including Let's Encrypt), using the HTTP-01 challenge"
    )
    version = acme.VERSION

    author = "Netflix"
    author_url = "https://github.com/netflix/lemur.git"

    options = [
        {
            "name": "acme_url",
            "type": "str",
            "required": True,
            "validation": "/^http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$/",
            "helpMessage": "Must be a valid web url starting with http[s]://",
        },
        {
            "name": "telephone",
            "type": "str",
            "default": "",
            "helpMessage": "Telephone to use",
        },
        {
            "name": "email",
            "type": "str",
            "default": "",
            "validation": "/^?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)$/",
            "helpMessage": "Email to use",
        },
        {
            "name": "certificate",
            "type": "textarea",
            "default": "",
            "validation": "/^-----BEGIN CERTIFICATE-----/",
            "helpMessage": "Certificate to use",
        },
        {
            "name": "tokenDestination",
            "type": "destinationSelect",
            "required": True,
            "helpMessage": "The destination to use to deploy the token.",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(ACMEHttpIssuerPlugin, self).__init__(*args, **kwargs)

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
            token_destination = None
            for option in json.loads(issuer_options["authority"].options):
                if option["name"] == "tokenDestination":
                    token_destination = destination_service.get(option["value"])

            if token_destination is None:
                raise Exception('No token_destination configured for this authority. Cant complete HTTP-01 challenge')

        destination_plugin = plugins.get(token_destination.plugin_name)

        for challenge in chall:
            response, validation = challenge.response_and_validation(acme_client.net.key)

            destination_plugin.upload_acme_token(challenge.chall.path, validation, token_destination.options)

            # Let the CA server know that we are ready for the challenge.
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
        return pem_certificate, pem_certificate_chain, validation[0:128]

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "acme"}
        plugin_options = options.get("plugin", {}).get("plugin_options")
        if not plugin_options:
            error = "Invalid options for lemur_acme plugin: {}".format(options)
            current_app.logger.error(error)
            raise InvalidConfiguration(error)
        # Define static acme_root based off configuration variable by default. However, if user has passed a
        # certificate, use this certificate as the root.
        acme_root = current_app.config.get("ACME_ROOT")
        for option in plugin_options:
            if option.get("name") == "certificate":
                acme_root = option.get("value")
        return acme_root, "", [role]

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        # Needed to override issuer function.
        pass

    def revoke_certificate(self, certificate, comments):
        self.acme = AcmeHandler()
        if not self.acme.reuse_account(certificate.authority):
            raise InvalidConfiguration("There is no ACME account saved, unable to revoke the certificate.")
        acme_client, _ = self.acme.setup_acme_client(certificate.authority)

        fullchain_com = jose.ComparableX509(
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, certificate.body))

        try:
            acme_client.revoke(fullchain_com, 0)  # revocation reason = 0
        except (errors.ConflictError, errors.ClientError, errors.Error) as e:
            # Certificate already revoked.
            current_app.logger.error("Certificate revocation failed with message: " + e.detail)
            metrics.send("acme_revoke_certificate_failure", "counter", 1)
            return False

        current_app.logger.warning("Certificate succesfully revoked: " + certificate.name)
        metrics.send("acme_revoke_certificate_success", "counter", 1)
        return True
