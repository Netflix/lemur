from lemur.plugins.bases import IssuerPlugin

from lemur.tests.vectors import SAN_CERT_STR, INTERMEDIATE_CERT_STR, IP_SAN_NO_CN_CERT_STR
from lemur.common.utils import parse_csr
from cryptography import x509
from cryptography.x509.oid import ExtensionOID


class TestIssuerPlugin(IssuerPlugin):
    title = "Test"
    slug = "test-issuer"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        # body, chain, external_id
        parsed_csr = parse_csr(csr)
        try:
            san = parsed_csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            if san and san.value.get_values_for_type(x509.IPAddress):
                return IP_SAN_NO_CN_CERT_STR, INTERMEDIATE_CERT_STR, None
        except x509.ExtensionNotFound:
            pass
        return SAN_CERT_STR, INTERMEDIATE_CERT_STR, None

    @staticmethod
    def create_authority(options):
        name = "test_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        return SAN_CERT_STR, "", [role]


class TestAsyncIssuerPlugin(IssuerPlugin):
    title = "Test Async"
    slug = "test-issuer-async"
    description = "Enables testing with pending certificates"

    author = "James Chuong"
    author_url = "https://github.com/jchuong"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        return "", "", 12345

    def get_ordered_certificate(self, pending_cert):
        return INTERMEDIATE_CERT_STR, SAN_CERT_STR, 54321

    @staticmethod
    def create_authority(options):
        name = "test_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        return SAN_CERT_STR, "", [role]

    def cancel_ordered_certificate(self, pending_certificate, **kwargs):
        return True
