from lemur.plugins.bases import SourcePlugin
from lemur.tests.vectors import WILDCARD_CERT_STR, WILDCARD_CERT_KEY, SAN_CERT_STR, SAN_CERT_KEY

from lemur.tests.factories import SignedCertificateFactory


class TestSourcePlugin(SourcePlugin):
    title = 'Test'
    slug = 'test-source'
    description = 'Enables testing'

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur.git'

    def __init__(self, *args, **kwargs):
        super(TestSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options):

        # Some existing certs
        certs = [
            {
                'body': SAN_CERT_STR,
                'private_key': SAN_CERT_KEY,
                'owner': 'bob@example.com',
                'creator': 'bob@example.com',
                'authority_id': 1
            },
            {
                'body': WILDCARD_CERT_STR,
                'private_key': WILDCARD_CERT_KEY,
                'owner': 'bob@example.com',
                'creator': 'bob@example.com',
                'external_id': 'somemediumlengthfakething'
            }
        ]

        # Some new certs with a variety of differences
        for r in range(1, 4):
            signed_cert = SignedCertificateFactory.get('source-certificate{}.example.org'.format(r))
            src_cert = {
                'body': signed_cert.cert_pem(),
                'private_key': signed_cert.key_pem(),
                'creator': 'bob@example.com',
                'owner': 'bob@example.com'
            }

            # second one, pass w/o owner
            if r == 2:
                src_cert.pop('owner')

            # third, set serial/ext id
            if r == 3:
                src_cert['serial'] = signed_cert.serial

            certs.append(src_cert)

        return certs

    def update_endpoint(self, endpoint, certificate):
        endpoints = [
            {
                
            }
        ]
