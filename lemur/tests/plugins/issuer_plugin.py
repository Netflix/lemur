from lemur.plugins.bases import IssuerPlugin

from lemur.tests.vectors import INTERNAL_VALID_SAN_STR, INTERNAL_VALID_LONG_STR


class TestIssuerPlugin(IssuerPlugin):
    title = 'Test'
    slug = 'test-issuer'
    description = 'Enables testing'

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        super(TestIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        return INTERNAL_VALID_LONG_STR, INTERNAL_VALID_SAN_STR, None

    @staticmethod
    def create_authority(options):
        role = {'username': '', 'password': '', 'name': 'test'}
        return INTERNAL_VALID_SAN_STR, "", [role]
