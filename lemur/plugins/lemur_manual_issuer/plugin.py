from typing import Optional, Tuple
import uuid

from flask import current_app

from lemur.common.utils import check_validation
from lemur.exceptions import InvalidConfiguration
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_manual_issuer as manual_issuer


class ManualIssuerPlugin(IssuerPlugin):
    title = "Manual"
    slug = "manual-issuer"
    description = "Enables the creation and signing of certificates by hand, using third-party tools or services."
    version = manual_issuer.VERSION

    options = [
        {
            "name": "public_certificate",
            "type": "textarea",
            "default": "",
            "validation": check_validation("^-----BEGIN CERTIFICATE-----"),
            "helpMessage": "External CA public certificate in PEM format. This is used to build the certificate chain and is required when creating an authority.",
        }
    ]

    author = "Philippe Desmarais"
    author_url = "https://github.com/netflix/lemur.git"

    @property
    def allows_auto_resolve(self):
        return False

    def create_certificate(self, _, options) -> Tuple[str, str, int]:
        """
        Directly returns a pending certificate.

        :param csr:
        :param options:
        :return:
        """
        current_app.logger.debug(
            f"Issuing a pending cert to complete later: {options}"
        )
        return "", "", int(uuid.uuid4())

    @staticmethod
    def create_authority(options) -> Tuple[Optional[str], Optional[str], Optional[str], list]:
        """
        The authority created here is bound to a single user-provided CA certificate. Only the CA's public cert is requested.

        :param options:
        :return:
        """
        current_app.logger.debug(
            f"Issuing new manual authority with options: {options}"
        )

        plugin_options = get_plugin_options(options)
        public_cert = get_option_pub_cert(plugin_options)

        roles = [
            {"username": "", "password": "", "name": options["name"] + "_admin"},
            {"username": "", "password": "", "name": options["name"] + "_operator"},
        ]
        return public_cert, None, None, roles

def get_plugin_options(options):
    plugin_options = options.get("plugin", {}).get("plugin_options")
    if not plugin_options:
        error = f"Invalid options for manual plugin: {options}"
        current_app.logger.error(error)
        raise InvalidConfiguration(error)
    return plugin_options

def get_option_pub_cert(plugin_options) -> Optional[str]:
    public_cert = None
    for option in plugin_options:
        if option.get("name") == "public_certificate":
            public_cert = option.get("value")
    return public_cert
