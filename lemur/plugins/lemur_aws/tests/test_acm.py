from moto import mock_acm, mock_sts
from lemur.common.utils import check_validation
from lemur.tests.vectors import ROOTCA_CERT_STR, INTERMEDIATE_CERT_STR, SAN_CERT_STR, SAN_CERT_KEY


def test_acm_source_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-acm-source")
    assert p


def test_acm_dest_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-acm-dest")
    assert p


@mock_sts()
@mock_acm()
def test_acm_plugin(app):
    from lemur.plugins.base import plugins

    cert_name = "testCert"
    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access ACM",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
    ]

    dp = plugins.get("aws-acm-dest")
    sp = plugins.get("aws-acm-source")

    chain = ROOTCA_CERT_STR + INTERMEDIATE_CERT_STR
    dp.upload(cert_name, SAN_CERT_STR, SAN_CERT_KEY, chain, options)

    certs = sp.get_certificates(options)
    assert len(certs) == 1

    dp.clean(certs[0], options)
    assert len(sp.get_certificates(options)) == 0
