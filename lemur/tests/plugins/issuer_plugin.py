from lemur.plugins.bases import IssuerPlugin

from lemur.tests.vectors import SAN_CERT_STR, INTERMEDIATE_CERT_STR


class TestIssuerPlugin(IssuerPlugin):
    title = "Test"
    slug = "test-issuer"
    description = "Enables testing"

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        super(TestIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        # body, chain, external_id
        return SAN_CERT_STR, INTERMEDIATE_CERT_STR, None

    @staticmethod
    def create_authority(options):
        role = {"username": "", "password": "", "name": "test"}
        return SAN_CERT_STR, "", [role]


class TestAsyncIssuerPlugin(IssuerPlugin):
    title = "Test Async"
    slug = "test-issuer-async"
    description = "Enables testing with pending certificates"

    author = "James Chuong"
    author_url = "https://github.com/jchuong"

    def __init__(self, *args, **kwargs):
        super(TestAsyncIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        return "", "", 12345

    def get_ordered_certificate(self, pending_cert):
        return INTERMEDIATE_CERT_STR, SAN_CERT_STR, 54321

    @staticmethod
    def create_authority(options):
        role = {"username": "", "password": "", "name": "test"}
        return SAN_CERT_STR, "", [role]

    def cancel_ordered_certificate(self, pending_certificate, **kwargs):
        return True
