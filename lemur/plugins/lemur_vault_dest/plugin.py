"""
.. module: lemur.plugins.lemur_vault_dest.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to hashi vault
     that can be pulled down by end point nodes.

.. moduleauthor:: Christopher Jolley <chris@alwaysjolley.com>
"""
import os
import re
import hvac
from flask import current_app

from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins.bases import SourcePlugin

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class VaultSourcePlugin(SourcePlugin):
    """ Class for importing certificates from Hashicorp Vault"""

    title = "Vault"
    slug = "vault-source"
    description = "Discovers all certificates in a given path"

    author = "Christopher Jolley"
    author_url = "https://github.com/alwaysjolley/lemur"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": "^https?://[a-zA-Z0-9.:-]+$",
            "helpMessage": "Valid URL to Hashi Vault instance",
        },
        {
            "name": "vaultKvApiVersion",
            "type": "select",
            "value": "2",
            "available": ["1", "2"],
            "required": True,
            "helpMessage": "Version of the Vault KV API to use",
        },
        {
            "name": "vaultAuthTokenFile",
            "type": "str",
            "required": True,
            "validation": "(/[^/]+)+",
            "helpMessage": "Must be a valid file path!",
        },
        {
            "name": "vaultMount",
            "type": "str",
            "required": True,
            "validation": r"^\S+$",
            "helpMessage": "Must be a valid Vault secrets mount name!",
        },
        {
            "name": "vaultPath",
            "type": "str",
            "required": True,
            "validation": "^([a-zA-Z0-9._-]+/?)+$",
            "helpMessage": "Must be a valid Vault secrets path",
        },
        {
            "name": "objectName",
            "type": "str",
            "required": True,
            "validation": "[0-9a-zA-Z.:_-]+",
            "helpMessage": "Object Name to search",
        },
    ]

    def get_certificates(self, options, **kwargs):
        """Pull certificates from objects in Hashicorp Vault"""
        data = []
        cert = []
        body = ""
        url = self.get_option("vaultUrl", options)
        token_file = self.get_option("vaultAuthTokenFile", options)
        mount = self.get_option("vaultMount", options)
        path = self.get_option("vaultPath", options)
        obj_name = self.get_option("objectName", options)
        api_version = self.get_option("vaultKvApiVersion", options)
        cert_filter = "-----BEGIN CERTIFICATE-----"
        cert_delimiter = "-----END CERTIFICATE-----"

        with open(token_file, "r") as tfile:
            token = tfile.readline().rstrip("\n")

        client = hvac.Client(url=url, token=token)
        client.secrets.kv.default_kv_version = api_version

        path = "{0}/{1}".format(path, obj_name)

        secret = get_secret(client, mount, path)
        for cname in secret["data"]:
            if "crt" in secret["data"][cname]:
                cert = secret["data"][cname]["crt"].split(cert_delimiter + "\n")
            elif "pem" in secret["data"][cname]:
                cert = secret["data"][cname]["pem"].split(cert_delimiter + "\n")
            else:
                for key in secret["data"][cname]:
                    if secret["data"][cname][key].startswith(cert_filter):
                        cert = secret["data"][cname][key].split(cert_delimiter + "\n")
                        break
            body = cert[0] + cert_delimiter
            if "chain" in secret["data"][cname]:
                chain = secret["data"][cname]["chain"]
            elif len(cert) > 1:
                if cert[1].startswith(cert_filter):
                    chain = cert[1] + cert_delimiter
                else:
                    chain = None
            else:
                chain = None
            data.append({"body": body, "chain": chain, "name": cname})
        return [
            dict(body=c["body"], chain=c.get("chain"), name=c["name"]) for c in data
        ]

    def get_endpoints(self, options, **kwargs):
        """ Not implemented yet """
        endpoints = []
        return endpoints


class VaultDestinationPlugin(DestinationPlugin):
    """Hashicorp Vault Destination plugin for Lemur"""

    title = "Vault"
    slug = "hashi-vault-destination"
    description = "Allow the uploading of certificates to Hashi Vault as secret"

    author = "Christopher Jolley"
    author_url = "https://github.com/alwaysjolley/lemur"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": "^https?://[a-zA-Z0-9.:-]+$",
            "helpMessage": "Valid URL to Hashi Vault instance",
        },
        {
            "name": "vaultKvApiVersion",
            "type": "select",
            "value": "2",
            "available": ["1", "2"],
            "required": True,
            "helpMessage": "Version of the Vault KV API to use",
        },
        {
            "name": "vaultAuthTokenFile",
            "type": "str",
            "required": True,
            "validation": "(/[^/]+)+",
            "helpMessage": "Must be a valid file path!",
        },
        {
            "name": "vaultMount",
            "type": "str",
            "required": True,
            "validation": r"^\S+$",
            "helpMessage": "Must be a valid Vault secrets mount name!",
        },
        {
            "name": "vaultPath",
            "type": "str",
            "required": True,
            "validation": "^([a-zA-Z0-9._-]+/?)+$",
            "helpMessage": "Must be a valid Vault secrets path",
        },
        {
            "name": "objectName",
            "type": "str",
            "required": False,
            "validation": "[0-9a-zA-Z.:_-]+",
            "helpMessage": "Name to bundle certs under, if blank use cn",
        },
        {
            "name": "bundleChain",
            "type": "select",
            "value": "cert only",
            "available": ["Nginx", "Apache", "PEM", "no chain"],
            "required": True,
            "helpMessage": "Bundle the chain into the certificate",
        },
        {
            "name": "sanFilter",
            "type": "str",
            "value": ".*",
            "required": False,
            "validation": ".*",
            "helpMessage": "Valid regex filter",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(VaultDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """
        cname = common_name(parse_certificate(body))

        url = self.get_option("vaultUrl", options)
        token_file = self.get_option("vaultAuthTokenFile", options)
        mount = self.get_option("vaultMount", options)
        path = self.get_option("vaultPath", options)
        bundle = self.get_option("bundleChain", options)
        obj_name = self.get_option("objectName", options)
        api_version = self.get_option("vaultKvApiVersion", options)
        san_filter = self.get_option("sanFilter", options)

        san_list = get_san_list(body)
        if san_filter:
            for san in san_list:
                try:
                    if not re.match(san_filter, san, flags=re.IGNORECASE):
                        current_app.logger.exception(
                            "Exception uploading secret to vault: invalid SAN: {}".format(
                                san
                            ),
                            exc_info=True,
                        )
                        os._exit(1)
                except re.error:
                    current_app.logger.exception(
                        "Exception compiling regex filter: invalid filter",
                        exc_info=True,
                    )

        with open(token_file, "r") as tfile:
            token = tfile.readline().rstrip("\n")

        client = hvac.Client(url=url, token=token)
        client.secrets.kv.default_kv_version = api_version

        if obj_name:
            path = "{0}/{1}".format(path, obj_name)
        else:
            path = "{0}/{1}".format(path, cname)

        secret = get_secret(client, mount, path)
        secret["data"][cname] = {}

        if not cert_chain:
            chain = ''
        else:
            chain = cert_chain

        if bundle == "Nginx":
            secret["data"][cname]["crt"] = "{0}\n{1}".format(body, chain)
            secret["data"][cname]["key"] = private_key
        elif bundle == "Apache":
            secret["data"][cname]["crt"] = body
            secret["data"][cname]["chain"] = chain
            secret["data"][cname]["key"] = private_key
        elif bundle == "PEM":
            secret["data"][cname]["pem"] = "{0}\n{1}\n{2}".format(
                body, chain, private_key
            )
        else:
            secret["data"][cname]["crt"] = body
            secret["data"][cname]["key"] = private_key
        if isinstance(san_list, list):
            secret["data"][cname]["san"] = san_list
        try:
            client.secrets.kv.create_or_update_secret(
                path=path, mount_point=mount, secret=secret["data"]
            )
        except ConnectionError as err:
            current_app.logger.exception(
                "Exception uploading secret to vault: {0}".format(err), exc_info=True
            )


def get_san_list(body):
    """ parse certificate for SAN names and return list, return empty list on error """
    san_list = []
    try:
        byte_body = body.encode("utf-8")
        cert = x509.load_pem_x509_certificate(byte_body, default_backend())
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_list = ext.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        pass
    finally:
        return san_list


def get_secret(client, mount, path):
    """ retreive existing data from mount path and return dictionary """
    result = {"data": {}}
    try:
        if client.secrets.kv.default_kv_version == "1":
            result = client.secrets.kv.v1.read_secret(path=path, mount_point=mount)
        else:
            result = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount
            )
            result = result['data']
    except ConnectionError:
        pass
    finally:
        return result
