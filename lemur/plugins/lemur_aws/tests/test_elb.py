import boto3
from moto import mock_sts, mock_elb


@mock_sts()
@mock_elb()
def test_get_all_elbs(app, aws_credentials):
    from lemur.plugins.lemur_aws.elb import get_all_elbs

    client = boto3.client("elb", region_name="us-east-1")

    elbs = get_all_elbs(account_number="123456789012", region="us-east-1")
    assert not elbs

    client.create_load_balancer(
        LoadBalancerName="example-lb",
        Listeners=[
            {
                "Protocol": "string",
                "LoadBalancerPort": 443,
                "InstanceProtocol": "tcp",
                "InstancePort": 5443,
                "SSLCertificateId": "tcp",
            }
        ],
    )

    elbs = get_all_elbs(account_number="123456789012", region="us-east-1")
    assert elbs
