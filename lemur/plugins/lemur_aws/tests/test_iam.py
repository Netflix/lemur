import pytest
from moto import mock_iam, mock_sts

from lemur.tests.vectors import EXTERNAL_VALID_STR, SAN_CERT_KEY


def test_get_name_from_arn():
    from lemur.plugins.lemur_aws.iam import get_name_from_arn

    arn = "arn:aws:iam::123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_name_from_arn(arn) == "tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_name_from_arn(arn) == "tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_name_from_arn(arn) == "tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    )

    arn = "arn:aws:acm:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_name_from_arn(arn) == "tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    )


def test_get_path_from_arn():
    from lemur.plugins.lemur_aws.iam import get_path_from_arn

    arn = "arn:aws:iam::123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_path_from_arn(arn) == ""
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_path_from_arn(arn) == "cloudfront"
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_path_from_arn(arn) == "cloudfront/2"
    )

    arn = "arn:aws:acm:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_path_from_arn(arn) == ""
    )


def test_get_registery_type_from_arn():
    from lemur.plugins.lemur_aws.iam import get_registry_type_from_arn

    arn = "arn:aws:iam::123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "iam"
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "iam"
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "iam"
    )

    arn = "arn:aws-us-gov:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "iam"
    )

    arn = "arn:aws-cn:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "iam"
    )

    arn = "arn:aws:acm:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "acm"
    )

    arn = "arn:aws-us-gov:acm:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "acm"
    )

    arn = "arn:aws-cn:acm:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "acm"
    )

    arn = "arn:aws:new:us-west-2:123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    assert (
        get_registry_type_from_arn(arn) == "unknown"
    )


def test_create_arn_from_cert():
    from lemur.plugins.lemur_aws.iam import create_arn_from_cert

    account_number = '123456789012'
    certificate_name = 'tttt2.netflixtest.net-NetflixInc-20150624-20150625'
    partition_commercial = 'aws'
    partition_gov = 'aws-us-gov'
    partition_cn = 'aws-cn'

    arn = "arn:aws:iam::123456789012:server-certificate/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = ""
    assert (
        create_arn_from_cert(account_number, partition_commercial, certificate_name, path) == arn
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = "cloudfront"
    assert (
        create_arn_from_cert(account_number, partition_commercial, certificate_name, path) == arn
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = "cloudfront/2"
    assert (
        create_arn_from_cert(account_number, partition_commercial, certificate_name, path) == arn
    )

    arn = "arn:aws:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = "cloudfront/2"
    assert (
        create_arn_from_cert(account_number, partition_commercial, certificate_name, path) == arn
    )

    arn = "arn:aws-us-gov:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = "cloudfront/2"
    assert (
        create_arn_from_cert(account_number, partition_gov, certificate_name, path) == arn
    )

    arn = "arn:aws-cn:iam::123456789012:server-certificate/cloudfront/2/tttt2.netflixtest.net-NetflixInc-20150624-20150625"
    path = "cloudfront/2"
    assert (
        create_arn_from_cert(account_number, partition_cn, certificate_name, path) == arn
    )


@pytest.mark.skipif(
    True, reason="this fails because moto is not currently returning what boto does"
)
@mock_sts()
@mock_iam()
def test_get_all_server_certs(app):
    from lemur.plugins.lemur_aws.iam import upload_cert, get_all_certificates

    upload_cert("123456789012", "testCert", EXTERNAL_VALID_STR, SAN_CERT_KEY)
    upload_cert("123456789012", "testCert2", EXTERNAL_VALID_STR, SAN_CERT_KEY, Tags=[{"Key": "lemur-test-ignore-iam", "Value": ""}])
    certs = get_all_certificates("123456789012")
    assert len(certs) == 1
