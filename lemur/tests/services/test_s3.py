import boto

from lemur.tests import LemurTestCase
from lemur.tests.constants import TEST_CERT

from lemur.certificates.models import Certificate

from moto import mock_s3


class S3TestCase(LemurTestCase):
    @mock_s3
    def test_save(self):
        from lemur.common.services.aws.s3 import save
        conn = boto.connect_s3()

        cert = Certificate(TEST_CERT)

        buck = conn.create_bucket('test')
        path = save(cert, 'private_key', None, 'csr_config', 'challenge')
        self.assertEqual(path, 'lemur/{}/{}/'.format(cert.issuer, cert.name))

        count = 0
        for key in buck.list():
            count += 1

        self.assertEqual(count, 4)
