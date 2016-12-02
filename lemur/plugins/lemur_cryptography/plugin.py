"""
.. module: lemur.plugins.lemur_cryptography.plugin
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import uuid

from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_cryptography as cryptography_issuer

from lemur.common.utils import generate_private_key


def build_root_certificate(options):
    private_key = generate_private_key(options.get('key_type'))

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.OID_COUNTRY_NAME, options['country']),
        x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, options['state']),
        x509.NameAttribute(x509.OID_LOCALITY_NAME, options['location']),
        x509.NameAttribute(x509.OID_ORGANIZATION_NAME, options['organization']),
        x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, options['organizational_unit']),
        x509.NameAttribute(x509.OID_COMMON_NAME, options['common_name'])
    ])

    builder = x509.CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=private_key.public_key(),
        not_valid_after=options['validity_end'],
        not_valid_before=options['validity_start'],
        serial_number=options['first_serial']
    )

    builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(options['common_name'])]), critical=False)

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # would like to use PKCS8 but AWS ELBs don't like it
        encryption_algorithm=serialization.NoEncryption()
    )

    return cert_pem, private_key_pem


def issue_certificate(csr, options):
    csr = x509.load_pem_x509_csr(csr.encode('utf-8'), default_backend())

    builder = x509.CertificateBuilder(
        issuer_name=x509.Name([
            x509.NameAttribute(
                x509.OID_ORGANIZATION_NAME,
                options['authority'].authority_certificate.issuer
            )]
        ),
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=options['validity_start'],
        not_valid_after=options['validity_end'],
        extensions=csr.extensions)

    # TODO figure out a better way to increment serial
    builder = builder.serial_number(int(uuid.uuid4()))

    private_key = serialization.load_pem_private_key(
        bytes(str(options['authority'].authority_certificate.private_key).encode('utf-8')),
        password=None,
        backend=default_backend()
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())

    return cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')


class CryptographyIssuerPlugin(IssuerPlugin):
    title = 'Cryptography'
    slug = 'cryptography-issuer'
    description = 'Enables the creation and signing of self-signed certificates'
    version = cryptography_issuer.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def create_certificate(self, csr, options):
        """
        Creates a certificate.

        :param csr:
        :param options:
        :return: :raise Exception:
        """
        current_app.logger.debug("Issuing new cryptography certificate with options: {0}".format(options))
        cert = issue_certificate(csr, options)
        return cert, ""

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        current_app.logger.debug("Issuing new cryptography authority with options: {0}".format(options))
        cert, private_key = build_root_certificate(options)
        roles = [
            {'username': '', 'password': '', 'name': options['name'] + '_admin'},
            {'username': '', 'password': '', 'name': options['name'] + '_operator'}
        ]
        return cert, private_key, "", roles
