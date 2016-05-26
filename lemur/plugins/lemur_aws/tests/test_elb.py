import boto
from moto import mock_sts, mock_elb


@mock_sts()
@mock_elb()
def test_get_all_elbs(app):
    from lemur.plugins.lemur_aws.elb import get_all_elbs
    conn = boto.ec2.elb.connect_to_region('us-east-1')
    elbs = get_all_elbs(account_number='123456789012', region='us-east-1')
    assert not elbs['LoadBalancerDescriptions']
    conn.create_load_balancer('example-lb', ['us-east-1a', 'us-east-1b'], [(443, 5443, 'tcp')])
    elbs = get_all_elbs(account_number='123456789012', region='us-east-1')
    assert elbs['LoadBalancerDescriptions']
