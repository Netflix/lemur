import boto3
from moto import mock_sts, mock_ec2, mock_elb, mock_elbv2, mock_iam


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
            }
        ],
    )

    elbs = get_all_elbs(account_number="123456789012", region="us-east-1")
    assert elbs

    client.create_load_balancer(
        LoadBalancerName="example-lb-ignored",
        Listeners=[
            {
                "Protocol": "string",
                "LoadBalancerPort": 443,
                "InstanceProtocol": "tcp",
                "InstancePort": 5443,
            }
        ],
        Tags=[
            {
                "Key": "lemur-test-ignore",
                "Value": "",
            }
        ],
    )

    elbs = get_all_elbs(account_number="123456789012", region="us-east-1")
    names = [elb["LoadBalancerName"] for elb in elbs]
    assert "example-lb" in names
    assert "example-lb-ignored" not in names


@mock_sts()
@mock_ec2()
@mock_elbv2()
def test_get_all_elbs_v2(app):
    from lemur.plugins.lemur_aws.elb import get_all_elbs_v2

    ec2 = boto3.resource("ec2", region_name="us-east-1")
    elbv2 = boto3.client("elbv2", region_name="us-east-1")

    elbs = get_all_elbs_v2(account_number="123456789012", region="us-east-1")
    assert not elbs

    vpc = ec2.create_vpc(CidrBlock="10.0.1.0/24")
    subnet1 = ec2.create_subnet(
        VpcId=vpc.id, CidrBlock="10.0.1.128/25", AvailabilityZone="us-east-1b"
    )
    elbv2.create_load_balancer(
        Name="test-lbv2",
        Subnets=[
            subnet1.id,
        ],
    )

    elbs = get_all_elbs_v2(account_number="123456789012", region="us-east-1")
    assert "test-lbv2" in [elb["LoadBalancerName"] for elb in elbs]

    elbv2.create_load_balancer(
        Name="test-lbv2-ignored",
        Subnets=[
            subnet1.id,
        ],
        Tags=[
            {
                "Key": "lemur-test-ignore",
                "Value": "",
            }
        ],
    )
    elbs = get_all_elbs_v2(account_number="123456789012", region="us-east-1")

    assert "test-lbv2" in [elb["LoadBalancerName"] for elb in elbs]
    assert "test-lbv2-ignored" not in [elb["LoadBalancerName"] for elb in elbs]


@mock_sts()
@mock_ec2
@mock_elbv2()
@mock_iam
def test_create_elb_with_https_listener_miscellaneous(app, aws_credentials):
    from lemur.plugins.lemur_aws import iam, elb

    endpoint_name = "example-lbv2"
    account_number = "123456789012"
    region_ue1 = "us-east-1"

    client = boto3.client("elbv2", region_name="us-east-1")
    ec2 = boto3.resource("ec2", region_name="us-east-1")

    # Create VPC
    vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24")

    # Create LB (elbv2) in above VPC
    assert create_load_balancer(client, ec2, vpc.id, endpoint_name)
    # Create target group
    target_group_arn = create_target_group(client, vpc.id)
    assert target_group_arn

    # Test get_load_balancer_arn_from_endpoint
    lb_arn = elb.get_load_balancer_arn_from_endpoint(
        endpoint_name, account_number=account_number, region=region_ue1
    )
    assert lb_arn

    # Test describe_listeners_v2
    listeners = elb.describe_listeners_v2(
        account_number=account_number, region=region_ue1, LoadBalancerArn=lb_arn
    )
    assert listeners
    assert not listeners["Listeners"]

    # Upload cert
    response = iam.upload_cert(
        "LemurTestCert", "testCert", "cert1", "cert2", account_number=account_number
    )
    assert response
    cert_arn = response["ServerCertificateMetadata"]["Arn"]
    assert cert_arn

    # Create https listener using above cert
    listeners = client.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
    )
    assert listeners
    listener_arn = listeners["Listeners"][0]["ListenerArn"]
    assert listener_arn

    assert listeners["Listeners"]
    for listener in listeners["Listeners"]:
        if listener["Port"] == 443:
            assert listener["Certificates"]
            assert cert_arn == listener["Certificates"][0]["CertificateArn"]

    # Test get_listener_arn_from_endpoint
    assert listener_arn == elb.get_listener_arn_from_endpoint(
        endpoint_name,
        443,
        account_number=account_number,
        region=region_ue1,
    )


def create_load_balancer(client, ec2, vpc_id, endpoint_name):
    subnet1 = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="172.28.7.192/26", AvailabilityZone="us-east-1a"
    )

    return client.create_load_balancer(
        Name=endpoint_name,
        Subnets=[
            subnet1.id,
        ],
    )


def create_target_group(client, vpc_id):
    response = client.create_target_group(
        Name="a-target",
        Protocol="HTTPS",
        Port=443,
        VpcId=vpc_id,
    )
    return response.get("TargetGroups")[0]["TargetGroupArn"]
