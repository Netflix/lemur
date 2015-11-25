"""
.. module: lemur.plugins.lemur_java.plugin
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import subprocess

from flask import current_app

from lemur.utils import mktempfile, mktemppath
from lemur.plugins.bases import ExportPlugin
from lemur.plugins import lemur_java as java
from lemur.common.utils import get_psuedo_random_string


def run_process(command):
    """
    Runs a given command with pOpen and wraps some
    error handling around it.
    :param command:
    :return:
    """
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        current_app.logger.debug(" ".join(command))
        current_app.logger.error(stderr)
        raise Exception(stderr)


class JavaExportPlugin(ExportPlugin):
    title = 'Java'
    slug = 'java-export'
    description = 'Attempts to generate a JKS keystore or truststore'
    version = java.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    additional_options = [
        {
            'name': 'type',
            'type': 'select',
            'required': True,
            'available': ['jks'],
            'helpMessage': 'Choose the format you wish to export',
        },
        {
            'name': 'passphrase',
            'type': 'str',
            'required': False,
            'helpMessage': 'If no passphrase is generated one will be generated for you.',
        },
        {
            'name': 'alias',
            'type': 'str',
            'required': False,
            'helpMessage': 'Enter the alias you wish to use for the keystore.',
        }
    ]

    @staticmethod
    def export(body, key, options, **kwargs):
        """
        Generates a Java Keystore or Truststore

        :param key:
        :param kwargs:
        :param body:
        :param options:
        """
        if options.get('passphrase'):
            passphrase = options['passphrase']
        else:
            passphrase = get_psuedo_random_string()

        with mktempfile() as cert_tmp:
            with open(cert_tmp, 'w') as f:
                f.write(body)
            with mktempfile() as key_tmp:
                with open(key_tmp, 'w') as f:
                    f.write(key)

                # Create PKCS12 keystore from private key and public certificate
                with mktempfile() as p12_tmp:
                    run_process([
                        "openssl",
                        "pkcs12",
                        "-export",
                        "-name", options.get('alias', 'cert'),
                        "-in", cert_tmp,
                        "-inkey", key_tmp,
                        "-out", p12_tmp,
                        "-password", "pass:{}".format(passphrase)
                    ])

                    # Convert PKCS12 keystore into a JKS keystore
                    with mktemppath() as jks_tmp:
                        run_process([
                            "keytool",
                            "-importkeystore",
                            "-destkeystore", jks_tmp,
                            "-srckeystore", p12_tmp,
                            "-srcstoretype", "PKCS12",
                            "-alias", options.get('alias', 'cert'),
                            "-srcstorepass", passphrase,
                            "-deststorepass", passphrase
                        ])

                        # Import signed cert in to JKS keystore
                        run_process([
                            "keytool",
                            "-importcert",
                            "-file", cert_tmp,
                            "-keystore", jks_tmp,
                            "-alias", "{0}_cert".format(options.get('alias'), 'cert'),
                            "-storepass", passphrase,
                            "-noprompt"
                        ])

                        with open(jks_tmp, 'rb') as f:
                            raw = f.read()

                        return raw
