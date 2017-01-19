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
from lemur.certificates.service import create_csr 

def build_certificate_authority(options):
    options['certificate_authority'] = True
    csr, private_key = create_csr(**options)
    cert_pem, chain_cert_pem = issue_certificate(csr, options, private_key)

    return cert_pem, private_key, chain_cert_pem


def issue_certificate(csr, options, private_key = None):
    csr = x509.load_pem_x509_csr(csr.encode('utf-8'), default_backend())

    if options.get("parent"):
        # creating intermediate authorities will have options['parent'] to specify the issuer
        # creating certificates will have options['authority'] to specify the issuer
        # This works around that by making sure options['authority'] can be referenced for either
        options['authority'] = options['parent']

    if options.get("authority"):
        # Issue certificate signed by an existing lemur_certificates authority
        issuer_subject = options['authority'].authority_certificate.subject
        issuer_private_key = options['authority'].authority_certificate.private_key
        chain_cert_pem = options['authority'].authority_certificate.body
        authority_key_identifier_public = options['authority'].authority_certificate.public_key
        authority_key_identifier_subject = x509.SubjectKeyIdentifier.from_public_key(authority_key_identifier_public)
        authority_key_identifier_issuer = issuer_subject
        authority_key_identifier_serial = int(options['authority'].authority_certificate.serial)
        # TODO figure out a better way to increment serial
        # New authorities have a value at options['serial_number'] that is being ignored here.
        serial = int(uuid.uuid4())
    else:
        # Issue certificate that is self-signed (new lemur_certificates root authority)
        issuer_subject = csr.subject
        issuer_private_key = private_key
        chain_cert_pem = ""
        authority_key_identifier_public = csr.public_key()
        authority_key_identifier_subject = None
        authority_key_identifier_issuer = csr.subject
        authority_key_identifier_serial = options['serial_number']
        # TODO figure out a better way to increment serial
        serial = int(uuid.uuid4())

    builder = x509.CertificateBuilder(
        issuer_name=issuer_subject,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=options['validity_start'],
        not_valid_after=options['validity_end'],
        serial_number=serial,
        extensions=csr.extensions._extensions)


    private_key = serialization.load_pem_private_key(
        bytes(str(issuer_private_key).encode('utf-8')),
        password=None,
        backend=default_backend()
    )

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())
    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    return cert_pem, chain_cert_pem


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
        cert_pem, chain_cert_pem = issue_certificate(csr, options)
        return cert, chain_cert_pem

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        current_app.logger.debug("Issuing new cryptography authority with options: {0}".format(options))
        cert_pem, private_key, chain_cert_pem = build_certificate_authority(options)
        roles = [
            {'username': '', 'password': '', 'name': options['name'] + '_admin'},
            {'username': '', 'password': '', 'name': options['name'] + '_operator'}
        ]
        return cert_pem, private_key, chain_cert_pem, roles
