from lemur import app
from lemur.tests import LemurTestCase
from lemur.tests.constants import TEST_CERT, TEST_KEY

from lemur.certificates.models import Certificate

from moto import mock_iam, mock_sts


class IAMTestCase(LemurTestCase):
    @mock_sts
    @mock_iam
    def test_get_all_server_certs(self):
        from lemur.common.services.aws.iam import upload_cert, get_all_server_certs
        cert = Certificate(TEST_CERT)
        upload_cert('1111', cert, TEST_KEY)
        certs = get_all_server_certs('1111')
        self.assertEquals(len(certs), 1)

    @mock_sts
    @mock_iam
    def test_get_server_cert(self):
        from lemur.common.services.aws.iam import upload_cert, get_cert_from_arn
        cert = Certificate(TEST_CERT)
        upload_cert('1111', cert, TEST_KEY)
        body, chain = get_cert_from_arn('arn:aws:iam::123456789012:server-certificate/AHB-dfdsflkj.net-NetflixInc-20140525-20150525')
        self.assertTrue(body)

    @mock_sts
    @mock_iam
    def test_upload_server_cert(self):
        from lemur.common.services.aws.iam import upload_cert
        cert = Certificate(TEST_CERT)
        response = upload_cert('1111', cert, TEST_KEY)
        self.assertEquals(response['upload_server_certificate_response']['upload_server_certificate_result']['server_certificate_metadata']['server_certificate_name'], 'AHB-dfdsflkj.net-NetflixInc-20140525-20150525')


