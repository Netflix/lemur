from moto import mock_iam, mock_sts

from lemur.tests.vectors import EXTERNAL_VALID_STR, PRIVATE_KEY_STR


def test_get_name_from_arn():
    from lemur.plugins.lemur_aws.iam import get_name_from_arn
    arn = 'arn:aws:iam::123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625'
    assert get_name_from_arn(arn) == 'tttt2.netflixtest.net-NetflixInc-20150624-20150625'


@mock_sts()
@mock_iam()
def test_get_all_server_certs(app):
    from lemur.plugins.lemur_aws.iam import upload_cert, get_all_server_certs
    upload_cert('123456789012', 'testCert', EXTERNAL_VALID_STR.decode('utf-8'), PRIVATE_KEY_STR.decode('utf-8'))
    certs = get_all_server_certs('123456789012')
    assert len(certs) == 1


@mock_sts()
@mock_iam()
def test_get_cert_from_arn(app):
    from lemur.plugins.lemur_aws.iam import upload_cert, get_cert_from_arn
    upload_cert('123456789012', 'testCert', EXTERNAL_VALID_STR.decode('utf-8'), PRIVATE_KEY_STR.decode('utf-8'))
    body, chain = get_cert_from_arn('arn:aws:iam::123456789012:server-certificate/testCert')
    assert body.replace('\n', '') == EXTERNAL_VALID_STR.decode('utf-8').replace('\n', '')
