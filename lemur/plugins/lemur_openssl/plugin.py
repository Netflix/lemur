"""
.. module: lemur.plugins.lemur_openssl.plugin
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import subprocess
import os
import arrow
import uuid
import string

from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from lemur.certificates.models import Certificate

from lemur.utils import mktempfile, mktemppath
from lemur.plugins.bases import ExportPlugin, IssuerPlugin
from lemur.plugins import lemur_openssl as openssl
from lemur.common.utils import get_psuedo_random_string

supported_hash_algorithms = {
    alg.name: alg
    for alg in (hashes.SHA224, hashes.SHA256, hashes.SHA384, hashes.SHA512, hashes.RIPEMD160, hashes.Whirlpool)
    }

VALID_FILENAME_CHARS = "-_.() %s%s" % (string.ascii_letters, string.digits)


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
    with mktempfile() as key_tmp:
        with open(key_tmp, 'w') as f:
            f.write(key)

        # Create PKCS12 keystore from private key and public certificate
        with mktempfile() as cert_tmp:
            with open(cert_tmp, 'w') as f:
                f.writelines([cert + "\n", chain + "\n"])

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


def get_ca_key(openssl_cert_path, ca_name):

    ca_dir = remove_disallowed_filename_chars(ca_name)

    root_ca_cert = os.path.join(openssl_cert_path, ca_dir, "ca.crt")
    root_ca_key = os.path.join(openssl_cert_path, ca_dir, "ca.key")

    if os.path.isfile(root_ca_key):
        current_app.logger.info('found root ca cert')
        with open(root_ca_cert, 'r') as myfile:
            data = myfile.read()
        return data
    else:
        current_app.logger.debug("The directory %s does not exist for authority %s " % (root_ca_key, ca_name))
    return None


def create_new_root_ca(openssl_cert_path, ca_name, subject, days, key_size, sign_algo):

    ca_dir = remove_disallowed_filename_chars(ca_name)

    current_app.logger.debug("The root CA directory: {0}".format(ca_dir))

    if not os.path.exists(ca_dir):
        current_app.logger.debug("The directory does not exist, creating")
        os.makedirs(os.path.join(openssl_cert_path, ca_dir))

    root_ca_cert = os.path.join(openssl_cert_path, ca_dir, "ca.crt")
    root_ca_key = os.path.join(openssl_cert_path, ca_dir, "ca.key")

    """
    Creates a root CA.
    """
    cert = run_process\
            ([
                "openssl",
                "req",
                "-x509",
                "-%s" % sign_algo,
                "-subj", subject,
                "-new",
                "-nodes",
                "-newkey", "rsa:%d" % key_size,
                "-keyform", "PEM",
                "-outform", "PEM",
                "-days", str(days),
                "-keyout", root_ca_key,
            ])

    with open(root_ca_cert, 'w') as out:
        out.write(cert)

    return cert


def create_new_cert(openssl_cert_path, csr, ca_name, not_before, not_after, algo):
    """
    Signs a CSR by way of the ca's key matching "ca_name".

    Implementation note: We must use cryptography here instead of
    """
    from cryptography.hazmat.primitives import serialization

    ca_crt = os.path.join(openssl_cert_path, ca_name, "ca.crt")
    ca_key = os.path.join(openssl_cert_path, ca_name, "ca.key")

    with open(ca_crt, 'rb') as cert_file:
        ca = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    with open(ca_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(),
                                                         password=None,
                                                         backend=default_backend())
    csr = x509.load_pem_x509_csr(csr, default_backend())

    current_app.logger.debug("CSR extensions: {0}".format(csr.extensions))

    builder = x509.CertificateBuilder(
        issuer_name=ca.subject,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=arrow.get(not_before),
        not_valid_after=arrow.get(not_after),
        extensions=csr.extensions)

    builder = builder.serial_number(int(uuid.uuid4()))

    cert = builder.sign(private_key, supported_hash_algorithms[algo](), default_backend())

    return cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )


def get_days(options):
    now = arrow.utcnow()
    then = arrow.get(options['validityEnd'])
    return (then - now).days


def remove_disallowed_filename_chars(filename):
    return ''.join(c if c in VALID_FILENAME_CHARS else '_' for c in filename.replace("_", "__"))


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
                create_pkcs12(body, chain, output_tmp, key, alias, passphrase)
                extension = "p12"
            else:
                raise Exception("Unable to export, unsupported type: {0}".format(type))

            with open(output_tmp, 'rb') as f:
                raw = f.read()

        return extension, passphrase, raw


class OpenSSLIssuerPlugin(IssuerPlugin):
    title = 'OpenSSL'
    slug = 'openssl-issuer'
    description = 'Enables the creation of certificates using OpenSSL.'

    author = 'Mikhail Khodorovskiy'
    author_url = 'https://github.com/mik373/lemur'

    def __init__(self, *args, **kwargs):
        super(OpenSSLIssuerPlugin, self).__init__(*args, **kwargs)

    # noinspection PyMethodOverriding
    def create_certificate(self, csr, issuer_options):

        """
        Creates a certificate

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        openssl_cert_path = current_app.config.get("OPENSSL_DIR")
        authority = issuer_options['authority']
        ca_name = authority.name
        root_ca = get_ca_key(openssl_cert_path, ca_name)

        if root_ca is None:
            raise Exception("Root CA %s does not exist" % ca_name)

        algo = Certificate(root_ca).signing_algorithm

        cert = create_new_cert(openssl_cert_path, csr, ca_name, issuer_options['validityStart'], issuer_options['validityEnd'], algo)

        return cert, root_ca

    # noinspection PyMethodOverriding
    def create_authority(self, options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """

        openssl_cert_path = current_app.config.get("OPENSSL_DIR")
        ca_name = unicode(options['caName'])

        if get_ca_key(openssl_cert_path, ca_name) is not None:
            raise Exception("Root CA %s already exists" % ca_name)

        key_type = options.get('keyType', 'RSA2048')
        if not key_type.startswith('RSA'):
            raise Exception("Unsupported keyType '%s', please use RSA" % key_type)
        key_size = int(key_type[len("RSA"):])

        sign_algo = 'sha256'
        if options.get('caSigningAlgo') not in ('sha256', 'sha256WithRSA'):
            raise Exception("Unsupported signing algorithm '%s', please use 'sha256WithRSA'" % options.get('caSigningAlgo'))

        open_ssl_ca_sub = '/CN={commonName}/OU={organizationalUnit}/O={organization}/L={location}/ST={state}/C={country}'.format(**options['caDN'])
        open_ssl_ca_days = get_days(options)

        root_ca = create_new_root_ca(openssl_cert_path, ca_name, open_ssl_ca_sub, open_ssl_ca_days, key_size, sign_algo)

        return root_ca, "", []
