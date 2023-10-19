"""
.. module: lemur.plugins.lemur_cryptography.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import uuid

from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from lemur.common.utils import parse_private_key
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_cryptography as cryptography_issuer

from lemur.certificates.service import create_csr


def build_certificate_authority(options):
    options["certificate_authority"] = True
    csr, private_key = create_csr(**options)

    if options.get("parent"):
        # Intermediate Cert Issuance
        cert_pem, chain_cert_pem = issue_certificate(csr, options, None)
    else:
        cert_pem, chain_cert_pem = issue_certificate(csr, options, private_key)

    return cert_pem, private_key, chain_cert_pem


def issue_certificate(csr, options, private_key=None):
    csr = x509.load_pem_x509_csr(csr.encode("utf-8"), default_backend())

    if options.get("parent"):
        # creating intermediate authorities will have options['parent'] to specify the issuer
        # creating certificates will have options['authority'] to specify the issuer
        # This works around that by making sure options['authority'] can be referenced for either
        options["authority"] = options["parent"]

    if options.get("authority"):
        # Issue certificate signed by an existing lemur_certificates authority
        issuer_subject = options["authority"].authority_certificate.subject
        assert (
            private_key is None
        ), "Private would be ignored, authority key used instead"
        private_key = options["authority"].authority_certificate.private_key
        chain_cert_pem = options["authority"].authority_certificate.body
        authority_key_identifier_public = options[
            "authority"
        ].authority_certificate.public_key
        authority_key_identifier_subject = x509.SubjectKeyIdentifier.from_public_key(
            authority_key_identifier_public
        )
        authority_key_identifier_issuer = issuer_subject
        authority_key_identifier_serial = int(
            options["authority"].authority_certificate.serial
        )
        # TODO figure out a better way to increment serial
        # New authorities have a value at options['serial_number'] that is being ignored here.
        serial = int(uuid.uuid4())
    else:
        # Issue certificate that is self-signed (new lemur_certificates root authority)
        issuer_subject = csr.subject
        chain_cert_pem = ""
        authority_key_identifier_public = csr.public_key()
        authority_key_identifier_subject = None
        authority_key_identifier_issuer = csr.subject
        authority_key_identifier_serial = options["serial_number"]
        # TODO figure out a better way to increment serial
        serial = int(uuid.uuid4())

    extensions = normalize_extensions(csr)

    builder = x509.CertificateBuilder(
        issuer_name=issuer_subject,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=options["validity_start"],
        not_valid_after=options["validity_end"],
        serial_number=serial,
        extensions=extensions,
    )

    for k, v in options.get("extensions", {}).items():
        if k == "authority_key_identifier":
            # One or both of these options may be present inside the aki extension
            (authority_key_identifier, authority_identifier) = (False, False)
            for k2, v2 in v.items():
                if k2 == "use_key_identifier" and v2:
                    authority_key_identifier = True
                if k2 == "use_authority_cert" and v2:
                    authority_identifier = True
            if authority_key_identifier:
                if authority_key_identifier_subject:
                    # FIXME in python-cryptography.
                    # from_issuer_subject_key_identifier(cls, ski) is looking for ski.value.digest
                    # but the digest of the ski is at just ski.digest. Until that library is fixed,
                    # this function won't work. The second line has the same result.
                    # aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(authority_key_identifier_subject)
                    aki = x509.AuthorityKeyIdentifier(
                        authority_key_identifier_subject.digest, None, None
                    )
                else:
                    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        authority_key_identifier_public
                    )
            elif authority_identifier:
                aki = x509.AuthorityKeyIdentifier(
                    None,
                    [x509.DirectoryName(authority_key_identifier_issuer)],
                    authority_key_identifier_serial,
                )
            builder = builder.add_extension(aki, critical=False)
        if k == "certificate_info_access":
            # FIXME: Implement the AuthorityInformationAccess extension
            # descriptions = [
            #     x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(u"http://FIXME")),
            #     x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(u"http://FIXME"))
            # ]
            # for k2, v2 in v.items():
            #     if k2 == 'include_aia' and v2 == True:
            #         builder = builder.add_extension(
            #             x509.AuthorityInformationAccess(descriptions),
            #             critical=False
            #         )
            pass
        if k == "crl_distribution_points":
            # FIXME: Implement the CRLDistributionPoints extension
            # FIXME: Not implemented in lemur/schemas.py yet https://github.com/Netflix/lemur/issues/662
            pass

    private_key = parse_private_key(private_key)

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    return cert_pem, chain_cert_pem


def normalize_extensions(csr):
    try:
        san_extension = csr.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_dnsnames = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        san_dnsnames = []
        san_extension = x509.Extension(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            True,
            x509.SubjectAlternativeName(san_dnsnames),
        )

    common_name = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    common_name = common_name[0].value

    if common_name not in san_dnsnames and " " not in common_name:
        # CommonName isn't in SAN and CommonName has no spaces that will cause idna errors
        # Create new list of GeneralNames for including in the SAN extension
        general_names = []
        try:
            # Try adding Subject CN as first SAN general_name
            general_names.append(x509.DNSName(common_name))
        except TypeError:
            # CommonName probably not a valid string for DNSName
            pass

        # Add all submitted SAN names to general_names
        for san in san_extension.value:
            general_names.append(san)

        san_extension = x509.Extension(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            True,
            x509.SubjectAlternativeName(general_names),
        )

    # Remove original san extension from CSR and add new SAN extension
    extensions = list(filter(filter_san_extensions, csr.extensions._extensions))
    if san_extension is not None and len(san_extension.value._general_names) > 0:
        extensions.append(san_extension)

    return extensions


def filter_san_extensions(ext):
    if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
        return False
    return True


class CryptographyIssuerPlugin(IssuerPlugin):
    title = "Cryptography"
    slug = "cryptography-issuer"
    description = "Enables the creation and signing of self-signed certificates"
    version = cryptography_issuer.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def create_certificate(self, csr, options):
        """
        Creates a certificate.

        :param csr:
        :param options:
        :return: :raise Exception:
        """
        current_app.logger.debug(
            f"Issuing new cryptography certificate with options: {options}"
        )
        cert_pem, chain_cert_pem = issue_certificate(csr, options)
        return cert_pem, chain_cert_pem, None

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        current_app.logger.debug(
            f"Issuing new cryptography authority with options: {options}"
        )
        cert_pem, private_key, chain_cert_pem = build_certificate_authority(options)
        roles = [
            {"username": "", "password": "", "name": options["name"] + "_admin"},
            {"username": "", "password": "", "name": options["name"] + "_operator"},
        ]
        return cert_pem, private_key, chain_cert_pem, roles
