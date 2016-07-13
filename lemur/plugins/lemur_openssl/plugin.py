"""
.. module: lemur.plugins.lemur_openssl.plugin
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from io import open
import subprocess

from flask import current_app

from lemur.utils import mktempfile, mktemppath
from lemur.plugins.bases import ExportPlugin
from lemur.plugins import lemur_openssl as openssl
from lemur.common.utils import get_psuedo_random_string


def run_process(command):
    """
    Runs a given command with pOpen and wraps some
    error handling around it.
    :param command:
    :return:
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    current_app.logger.debug(command)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        current_app.logger.debug(" ".join(command))
        current_app.logger.error(stderr)
        raise Exception(stderr)


def create_pkcs12(cert, chain, p12_tmp, key, alias, passphrase):
    """
    Creates a pkcs12 formated file.
    :param cert:
    :param chain:
    :param p12_tmp:
    :param key:
    :param alias:
    :param passphrase:
    """
    if isinstance(cert, bytes):
        cert = cert.decode('utf-8')

    if isinstance(chain, bytes):
        chain = chain.decode('utf-8')

    if isinstance(key, bytes):
        key = key.decode('utf-8')

    with mktempfile() as key_tmp:
        with open(key_tmp, 'w') as f:
            f.write(key)

        # Create PKCS12 keystore from private key and public certificate
        with mktempfile() as cert_tmp:
            with open(cert_tmp, 'w') as f:
                f.writelines([cert.strip() + "\n", chain.strip() + "\n"])

            run_process([
                "openssl",
                "pkcs12",
                "-export",
                "-name", alias,
                "-in", cert_tmp,
                "-inkey", key_tmp,
                "-out", p12_tmp,
                "-password", "pass:{}".format(passphrase)
            ])


class OpenSSLExportPlugin(ExportPlugin):
    title = 'OpenSSL'
    slug = 'openssl-export'
    description = 'Is a loose interface to openssl and support various formats'
    version = openssl.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    options = [
        {
            'name': 'type',
            'type': 'select',
            'required': True,
            'available': ['PKCS12 (.p12)'],
            'helpMessage': 'Choose the format you wish to export',
        },
        {
            'name': 'passphrase',
            'type': 'str',
            'required': False,
            'helpMessage': 'If no passphrase is given one will be generated for you, we highly recommend this. Minimum length is 8.',
            'validation': ''
        },
        {
            'name': 'alias',
            'type': 'str',
            'required': False,
            'helpMessage': 'Enter the alias you wish to use for the keystore.',
        }
    ]

    def export(self, body, chain, key, options, **kwargs):
        """
        Generates a Java Keystore or Truststore

        :param key:
        :param chain:
        :param body:
        :param options:
        :param kwargs:
        """
        if self.get_option('passphrase', options):
            passphrase = self.get_option('passphrase', options)
        else:
            passphrase = get_psuedo_random_string()

        if self.get_option('alias', options):
            alias = self.get_option('alias', options)
        else:
            alias = "blah"

        type = self.get_option('type', options)

        with mktemppath() as output_tmp:
            if type == 'PKCS12 (.p12)':
                if not key:
                    raise Exception("Private Key required by {0}".format(type))

                create_pkcs12(body, chain, output_tmp, key, alias, passphrase)
                extension = "p12"
            else:
                raise Exception("Unable to export, unsupported type: {0}".format(type))

            with open(output_tmp, 'rb') as f:
                raw = f.read()

        return extension, passphrase, raw
