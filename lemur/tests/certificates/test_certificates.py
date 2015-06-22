import os
import shutil
import boto

from lemur import app
from lemur.tests import LemurTestCase
from lemur.tests.constants import TEST_CERT, TEST_KEY

from moto import mock_iam, mock_sts, mock_s3


class CertificateTestCase(LemurTestCase):
    def test_create_challenge(self):
        from lemur.certificates.service import create_challenge
        self.assertTrue(len(create_challenge()) >= 24)

    def test_hash_domains(self):
        from lemur.certificates.service import hash_domains
        h = hash_domains(['netflix.com', 'www.netflix.com', 'movies.netflix.com'])
        self.assertEqual('c9c83253b46c7c1245c100ed3f7045eb', h)

    def test_create_csr(self):
        from lemur.certificates.service import create_csr
        from lemur.tests.certificates.test_csr import TEST_CSR
        path = create_csr(['netflix.com'], TEST_CSR)
        files = len(os.listdir(path))
        self.assertEqual(files, 4)
        shutil.rmtree(path)

    def test_create_san_csr(self):
        from lemur.certificates.service import create_csr
        from lemur.tests.certificates.test_csr import TEST_CSR
        path = create_csr(['netflix.com', 'www.netflix.com'], TEST_CSR)
        files = len(os.listdir(path))
        self.assertEqual(files, 4)
        shutil.rmtree(path)

    def test_create_path(self):
        from lemur.certificates.service import create_path
        path = create_path("blah")
        self.assertIn('blah', path)
        shutil.rmtree(path)

    @mock_s3
    @mock_sts
    @mock_iam
    def test_save_cert(self):
        from lemur.certificates.service import save_cert
        from lemur.common.services.aws.iam import get_all_server_certs
        conn = boto.connect_s3()
        bucket = conn.create_bucket(app.config.get('S3_BUCKET'))
        cert = save_cert(TEST_CERT, TEST_KEY, None, "blah", "blah", [1])
        count = 0
        for key in bucket.list():
            count += 1

        self.assertEqual(count, 4)
        certs = get_all_server_certs('1111')
        self.assertEqual(len(certs), 1)

#    @mock_s3
#    @mock_sts
#    @mock_iam
#    def test_upload_cert(self):
#        from lemur.certificates.service import upload
#        from lemur.common.services.aws.iam import get_all_server_certs
#        conn = boto.connect_s3()
#        bucket = conn.create_bucket(app.config.get('S3_BUCKET'))
#
#        cert_up = {"public_cert": TEST_CERT, "private_key": TEST_KEY, "owner": "test@example.com", "accounts_ids": ['1111']}
#
#        cert_name = upload(**cert_up)
#        valid_name = 'AHB-dfdsflkj.net-NetflixInc-20140525-20150525'
#        self.assertEqual(cert_name, valid_name)
#
#        app.logger.debug(cert_name)
#        count = 0
#
#        for key in bucket.list():
#            count += 1
#
#        self.assertEqual(count, 2)
#        certs = get_all_server_certs('179727101194')
#        self.assertEqual(len(certs), 1)
#
#
#
