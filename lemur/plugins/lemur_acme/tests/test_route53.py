import boto3
import pytest
from moto import mock_route53, mock_sts

from lemur.plugins.lemur_acme import route53


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _create_zone(r53_client, name):
    return r53_client.create_hosted_zone(
        Name=name,
        CallerReference=name,
        HostedZoneConfig={"PrivateZone": False, "Comment": ""},
    )["HostedZone"]["Id"]


@mock_sts()
@mock_route53()
def test_find_zone_id_single_match(app, aws_credentials):
    """Single matching zone is returned."""
    r53 = boto3.client("route53", region_name="us-east-1")
    zone_id = _create_zone(r53, "acme-certs.staging.dog")

    result = route53.find_zone_id(
        "_acme-challenge.us1.michelada.staging.dog.acme-certs.staging.dog",
        account_number="123456789012",
    )
    assert result == zone_id


@mock_sts()
@mock_route53()
def test_find_zone_id_prefers_most_specific(app, aws_credentials):
    """Most specific (longest) zone wins when parent and child are both in the account.

    This is the CNAME delegation scenario: acme-certs.staging.dog and staging.dog
    coexist in the same account. Lemur must write the challenge TXT to the delegated
    sub-zone, not to the parent.
    """
    r53 = boto3.client("route53", region_name="us-east-1")
    _create_zone(r53, "staging.dog")
    child_id = _create_zone(r53, "acme-certs.staging.dog")

    result = route53.find_zone_id(
        "_acme-challenge.us1.michelada.staging.dog.acme-certs.staging.dog",
        account_number="123456789012",
    )
    assert result == child_id


@mock_sts()
@mock_route53()
def test_find_zone_id_no_match_raises(app, aws_credentials):
    """Raises ValueError when no zone matches."""
    boto3.client("route53", region_name="us-east-1")

    with pytest.raises(ValueError, match="Unable to find a Route53 hosted zone"):
        route53.find_zone_id(
            "_acme-challenge.example.com",
            account_number="123456789012",
        )
