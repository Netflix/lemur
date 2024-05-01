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

from acme.errors import PollError, WildcardUnsupportedError
from acme.messages import Error as AcmeError
from botocore.exceptions import ClientError
from flask import current_app
from sentry_sdk import capture_exception

from lemur.authorizations import service as authorization_service
from lemur.common.utils import check_validation, drop_last_cert_from_chain
from lemur.constants import CRLReason, EMAIL_RE
from lemur.dns_providers import service as dns_provider_service
from lemur.exceptions import InvalidConfiguration
from lemur.extensions import metrics

from lemur.plugins import lemur_acme as acme
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins.lemur_acme.acme_handlers import AcmeHandler, AcmeDnsHandler
from lemur.plugins.lemur_acme.challenge_types import AcmeHttpChallenge, AcmeDnsChallenge


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
            "validation": check_validation(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$_@.&+-]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"),
            "helpMessage": "ACME resource URI. Must be a valid web url starting with http[s]://",
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
            "validation": EMAIL_RE.pattern,
            "helpMessage": "Email to use",
        },
        {
            "name": "certificate",
            "type": "textarea",
            "default": "",
            "validation": check_validation("^-----BEGIN CERTIFICATE-----"),
            "helpMessage": "ACME root certificate",
        },
        {
            "name": "store_account",
            "type": "bool",
            "required": False,
            "helpMessage": "Disable to create a new account for each ACME request",
            "default": False,
        },
        {
            "name": "eab_kid",
            "type": "str",
            "required": False,
            "helpMessage": "Key identifier for the external account.",
        },
        {
            "name": "eab_hmac_key",
            "type": "str",
            "required": False,
            "helpMessage": "HMAC key for the external account.",
        },
        {
            "name": "acme_private_key",
            "type": "textarea",
            "default": "",
            "required": False,
            "helpMessage": "Account Private Key. Will be encrypted.",
        },
        {
            "name": "acme_regr",
            "type": "textarea",
            "default": "",
            "required": False,
            "helpMessage": "Account Registration",
        },
        {
            "name": "drop_last_cert_from_chain",
            "type": "bool",
            "required": False,
            "helpMessage": "Drops the last certificate, i.e., the Cross Signed root, from the Chain",
            "default": False,
        }
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
            capture_exception()
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

        if self.options and "drop_last_cert_from_chain" in self.options \
                and self.options.get("drop_last_cert_from_chain") is True:
            # skipping the last element
            cert["chain"] = drop_last_cert_from_chain(cert["chain"])

        return cert

    def get_ordered_certificates(self, pending_certs):
        self.acme = AcmeDnsHandler()
        self.acme_dns_challenge = AcmeDnsChallenge()
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
                    capture_exception()
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
                capture_exception()
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

                if self.options and "drop_last_cert_from_chain" in self.options \
                        and self.options.get("drop_last_cert_from_chain") is True:
                    cert["chain"] = drop_last_cert_from_chain(cert["chain"])

            except (PollError, AcmeError, Exception) as e:
                capture_exception()
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
                self.acme_dns_challenge.cleanup(
                    entry["authorizations"], entry["acme_client"]
                )
        return certs

    def create_certificate(self, csr, issuer_options):
        """
        Creates an ACME certificate using the DNS-01 challenge.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        acme_dns_challenge = AcmeDnsChallenge()

        return acme_dns_challenge.create_certificate(csr, issuer_options)

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        name = "acme_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}

        plugin_options = options.get("plugin", {}).get("plugin_options")
        if not plugin_options:
            error = f"Invalid options for lemur_acme plugin: {options}"
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

    def revoke_certificate(self, certificate, reason):
        self.acme = AcmeDnsHandler()
        crl_reason = CRLReason.unspecified
        if "crl_reason" in reason:
            crl_reason = CRLReason[reason["crl_reason"]]

        return self.acme.revoke_certificate(certificate, crl_reason.value)


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
            "validation": check_validation(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$_@.&+-]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"),
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
            "validation": EMAIL_RE.pattern,
            "helpMessage": "Email to use",
        },
        {
            "name": "certificate",
            "type": "textarea",
            "default": "",
            "validation": check_validation("^-----BEGIN CERTIFICATE-----"),
            "helpMessage": "ACME root Certificate",
        },
        {
            "name": "store_account",
            "type": "bool",
            "required": False,
            "helpMessage": "Disable to create a new account for each ACME request",
            "default": False,
        },
        {
            "name": "eab_kid",
            "type": "str",
            "default": "",
            "required": False,
            "helpMessage": "Key identifier for the external account.",
        },
        {
            "name": "eab_hmac_key",
            "type": "str",
            "default": "",
            "required": False,
            "helpMessage": "HMAC key for the external account.",
        },
        {
            "name": "acme_private_key",
            "type": "textarea",
            "default": "",
            "required": False,
            "helpMessage": "Account Private Key. Will be encrypted.",
        },
        {
            "name": "acme_regr",
            "type": "textarea",
            "default": "",
            "required": False,
            "helpMessage": "Account Registration",
        },
        {
            "name": "tokenDestination",
            "type": "destinationSelect",
            "required": True,
            "helpMessage": "The destination to use to deploy the token.",
        },
        {
            "name": "drop_last_cert_from_chain",
            "type": "bool",
            "required": False,
            "helpMessage": "Drops the last certificate, i.e., the Cross Signed root, from the Chain",
            "default": False,
        }
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
        name = "acme_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}

        plugin_options = options.get("plugin", {}).get("plugin_options")
        if not plugin_options:
            error = f"Invalid options for lemur_acme plugin: {options}"
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

    def revoke_certificate(self, certificate, reason):
        self.acme = AcmeHandler()

        crl_reason = CRLReason.unspecified
        if "crl_reason" in reason:
            crl_reason = CRLReason[reason["crl_reason"]]

        return self.acme.revoke_certificate(certificate, crl_reason.value)
