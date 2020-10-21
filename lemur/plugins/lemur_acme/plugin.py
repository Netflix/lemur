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
import json

import OpenSSL.crypto
import josepy as jose
from acme import errors
from acme.errors import PollError, WildcardUnsupportedError
from acme.messages import Error as AcmeError
from botocore.exceptions import ClientError
from flask import current_app

from lemur.authorizations import service as authorization_service
from lemur.dns_providers import service as dns_provider_service
from lemur.exceptions import InvalidConfiguration, UnknownProvider
from lemur.extensions import metrics, sentry

from lemur.plugins import lemur_acme as acme
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins.lemur_acme import cloudflare, dyn, route53, ultradns, powerdns
from lemur.plugins.lemur_acme.acme_handlers import AcmeHandler, AcmeDnsHandler
from lemur.plugins.lemur_acme.challenge_types import AcmeHttpChallenge


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
        acme_http_challenge = AcmeHttpChallenge()

        return acme_http_challenge.create_certificate(csr, issuer_options)

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
