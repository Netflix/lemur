from lemur.plugins.bases import SourcePlugin
from lemur.tests.vectors import WILDCARD_CERT_STR, WILDCARD_CERT_KEY, SAN_CERT_STR, SAN_CERT_KEY


class TestSourcePlugin(SourcePlugin):
    title = 'Test'
    slug = 'test-source'
    description = 'Enables testing'

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        super(TestSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options):
        return [
            {
                'body': SAN_CERT_STR,
                'private_key': SAN_CERT_KEY,
                'owner': 'bob@example.com',
                'creator': 'bob@example.com'
            },
            {
                'body': WILDCARD_CERT_STR,
                'private_key': WILDCARD_CERT_KEY,
                'owner': 'bob@example.com',
                'creator': 'bob@example.com'
            }
        ]

    def update_endpoint(self, endpoint, certificate):
        return
