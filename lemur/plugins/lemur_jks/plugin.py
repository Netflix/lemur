"""
.. module: lemur.plugins.lemur_jks.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Marti Raudsepp <marti@juffo.org>
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from jks import PrivateKeyEntry, KeyStore, TrustedCertEntry

from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate, parse_cert_chain, parse_private_key, check_validation
from lemur.plugins import lemur_jks as jks
from lemur.plugins.bases import ExportPlugin


def cert_chain_as_der(cert, chain):
    """Return a certificate and its chain in a list format, as expected by pyjks."""

    certs = [parse_certificate(cert)]
    certs.extend(parse_cert_chain(chain))
    # certs (list) – A list of certificates, as byte strings. The first one should be the one belonging to the private
    # key, the others the chain (in correct order).
    return [cert.public_bytes(encoding=serialization.Encoding.DER) for cert in certs]


def create_truststore(cert, chain, alias, passphrase):
    entries = []
    for idx, cert_bytes in enumerate(cert_chain_as_der(cert, chain)):
        # The original cert gets name <ALIAS>_cert, first chain element is <ALIAS>_cert_1, etc.
        cert_alias = alias + "_cert" + (f"_{idx}" if idx else "")
        entries.append(TrustedCertEntry.new(cert_alias, cert_bytes))

    return KeyStore.new("jks", entries).saves(passphrase)


def create_keystore(cert, chain, key, alias, passphrase):
    certs_bytes = cert_chain_as_der(cert, chain)
    key_bytes = parse_private_key(key).private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    entry = PrivateKeyEntry.new(alias, certs_bytes, key_bytes)

    return KeyStore.new("jks", [entry]).saves(passphrase)


class JavaTruststoreExportPlugin(ExportPlugin):
    title = "Java Truststore (JKS)"
    slug = "java-truststore-jks"
    description = "Generates a JKS truststore"
    requires_key = False
    version = jks.VERSION

    author = "Marti Raudsepp"
    author_url = "https://github.com/intgr"

    options = [
        {
            "name": "alias",
            "type": "str",
            "required": False,
            "helpMessage": "Enter the alias you wish to use for the truststore.",
        },
        {
            "name": "passphrase",
            "type": "str",
            "required": False,
            "helpMessage": "If no passphrase is given one will be generated for you, we highly recommend this.",
            "validation": check_validation(""),
        },
    ]

    def export(self, body, chain, key, options, **kwargs):
        """
        Generates a Java Truststore
        """

        if self.get_option("alias", options):
            alias = self.get_option("alias", options)
        else:
            alias = common_name(parse_certificate(body))

        if self.get_option("passphrase", options):
            passphrase = self.get_option("passphrase", options)
        else:
            passphrase = Fernet.generate_key().decode("utf-8")

        raw = create_truststore(body, chain, alias, passphrase)

        return "jks", passphrase, raw


class JavaKeystoreExportPlugin(ExportPlugin):
    title = "Java Keystore (JKS)"
    slug = "java-keystore-jks"
    description = "Generates a JKS keystore"
    version = jks.VERSION

    author = "Marti Raudsepp"
    author_url = "https://github.com/intgr"

    options = [
        {
            "name": "passphrase",
            "type": "str",
            "required": False,
            "helpMessage": "If no passphrase is given one will be generated for you, we highly recommend this.",
            "validation": check_validation(""),
        },
        {
            "name": "alias",
            "type": "str",
            "required": False,
            "helpMessage": "Enter the alias you wish to use for the keystore.",
        },
    ]

    def export(self, body, chain, key, options, **kwargs):
        """
        Generates a Java Keystore
        """

        if self.get_option("passphrase", options):
            passphrase = self.get_option("passphrase", options)
        else:
            passphrase = Fernet.generate_key().decode("utf-8")

        if self.get_option("alias", options):
            alias = self.get_option("alias", options)
        else:
            alias = common_name(parse_certificate(body))

        raw = create_keystore(body, chain, key, alias, passphrase)

        return "jks", passphrase, raw
