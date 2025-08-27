from collections import namedtuple
from os.path import join
import boto3
from moto import mock_aws
from pytest import raises


def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-s3")
    assert p


def test_s3_default_prefix(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-s3")
    assert p.get_option("prefix", p.options) is not None


@mock_aws
def test_upload_invalid_prefix(app):
    from lemur.common.utils import check_validation
    from lemur.plugins.base import plugins

    bucket = "public-bucket"
    account = "123456789012"
    prefix = "/invalid"
    token_content = "Challenge"
    token_name = "TOKEN"
    token_path = ".well-known/acme-challenge/" + token_name

    additional_options = [
        {
            "name": "bucket",
            "value": bucket,
            "type": "str",
            "required": True,
            "validation": check_validation(r"[0-9a-z.-]{3,63}"),
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "value": account,
            "required": True,
            "validation": check_validation(r"[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access S3",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
        {
            "name": "encrypt",
            "type": "bool",
            "value": False,
            "required": False,
            "helpMessage": "Enable server side encryption",
            "default": True,
        },
        {
            "name": "prefix",
            "type": "str",
            "value": prefix,
            "required": False,
            "helpMessage": "Must be a valid S3 object prefix!",
        },
    ]

    s3_client = boto3.client('s3')
    s3_client.create_bucket(Bucket=bucket)
    p = plugins.get("aws-s3")

    with raises(ValueError) as e:
        p.upload_acme_token(token_path=token_path,
                           token_content=token_content,
                           token=token_content,
                           options=additional_options)
    assert "'prefix' cannot be validated" in str(e)


@mock_aws
def test_clean(app):
    from lemur.common.utils import check_validation
    from lemur.plugins.base import plugins

    bucket = "public-bucket"
    account = "123456789012"
    prefix = "some-path/more-path/"

    additional_options = [
        {
            "name": "bucket",
            "value": bucket,
            "type": "str",
            "required": True,
            "validation": check_validation(r"[0-9a-z.-]{3,63}"),
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "value": account,
            "required": True,
            "validation": check_validation(r"[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access S3",
        },
        {
            "name": "prefix",
            "type": "str",
            "value": prefix,
            "required": False,
            "helpMessage": "Must be a valid S3 object prefix!",
        },
    ]

    s3_client = boto3.client('s3')
    s3_client.create_bucket(Bucket=bucket)

    p = plugins.get("aws-s3")
    Certificate = namedtuple("Certificate", ["name", "body", "private_key", "chain"])
    certificate = Certificate(name="certificate", body="body", private_key="private_key", chain="chain")
    s3_client.put_object(
        Bucket=bucket,
        Body="PEM_DATA",
        Key=join(prefix, f"{certificate.name}.pem"),
    )
    assert s3_client.list_objects(Bucket=bucket)["Contents"]
    p.clean(certificate, additional_options)
    assert "Contents" not in s3_client.list_objects(Bucket=bucket)


@mock_aws
def test_upload_acme_token(app):
    from lemur.common.utils import check_validation
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws.s3 import get

    bucket = "public-bucket"
    account = "123456789012"
    prefix = "some-path/more-path/"
    token_content = "Challenge"
    token_name = "TOKEN"
    token_path = ".well-known/acme-challenge/" + token_name

    additional_options = [
        {
            "name": "bucket",
            "value": bucket,
            "type": "str",
            "required": True,
            "validation": check_validation(r"[0-9a-z.-]{3,63}"),
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "value": account,
            "required": True,
            "validation": check_validation(r"[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access S3",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
        {
            "name": "encrypt",
            "type": "bool",
            "value": False,
            "required": False,
            "helpMessage": "Enable server side encryption",
            "default": True,
        },
        {
            "name": "prefix",
            "type": "str",
            "value": prefix,
            "required": False,
            "helpMessage": "Must be a valid S3 object prefix!",
        },
    ]

    s3_client = boto3.client('s3')
    s3_client.create_bucket(Bucket=bucket)
    p = plugins.get("aws-s3")

    response = p.upload_acme_token(token_path=token_path,
                                   token_content=token_content,
                                   token=token_content,
                                   options=additional_options)
    assert response

    response = get(bucket_name=bucket,
                   prefixed_object_name=prefix + token_name,
                   encrypt=False,
                   account_number=account)

    # put data, and getting the same data
    assert (response == token_content)

    response = p.delete_acme_token(token_path=token_path,
                                   options=additional_options,
                                   account_number=account)
    assert response


@mock_aws
def test_get_all_elb_and_elbv2s(app, aws_credentials):
    from copy import deepcopy
    from lemur.plugins.lemur_aws.elb import get_load_balancer_arn_from_endpoint
    from lemur.plugins.base import plugins
    from lemur.plugins.utils import set_plugin_option

    acm_client = boto3.client("acm", region_name="us-east-1")
    acm_request_response = acm_client.request_certificate(
        DomainName="test.example.com",
        DomainValidationOptions=[
            {"DomainName": "test.example.com", "ValidationDomain": "test.example.com"},
        ],
    )
    arn1 = acm_request_response["CertificateArn"]
    cert_name1 = arn1.split("/")[-1]
    acm_request_response = acm_client.request_certificate(
        DomainName="test2.example.com",
        DomainValidationOptions=[
            {"DomainName": "test2.example.com", "ValidationDomain": "test2.example.com"},
        ],
    )
    arn2 = acm_request_response["CertificateArn"]
    cert_name2 = arn2.split("/")[-1]
    client = boto3.client("elb", region_name="us-east-1")

    client.create_load_balancer(
        LoadBalancerName="example-lb",
        Listeners=[
            {
                "Protocol": "string",
                "LoadBalancerPort": 443,
                "InstanceProtocol": "tcp",
                "InstancePort": 5443,
                "SSLCertificateId": arn1,
            }
        ],
    )

    ec2 = boto3.resource("ec2", region_name="us-east-1")
    elbv2 = boto3.client("elbv2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.1.0/24")
    subnet1 = ec2.create_subnet(
        VpcId=vpc.id,
        CidrBlock="10.0.1.128/25",
        AvailabilityZone="us-east-1b"
    )
    elbv2.create_load_balancer(
        Name="test-lbv2",
        Subnets=[
            subnet1.id,
        ],
    )
    lb_arn = get_load_balancer_arn_from_endpoint("test-lbv2",
                                                 account_number="123456789012",
                                                 region="us-east-1")
    target_group_arn = elbv2.create_target_group(
        Name="a-target",
        Protocol="HTTPS",
        Port=443,
        VpcId=vpc.id).get("TargetGroups")[0]["TargetGroupArn"]
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTPS",
        Port=1443,
        Certificates=[{"CertificateArn": arn2}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
    )

    aws_source = plugins.get("aws-source")
    options = deepcopy(aws_source.options)
    set_plugin_option("accountNumber", "123456789012", options)
    set_plugin_option("endpointType", "elb", options)
    set_plugin_option("regions", "us-east-1", options)
    elbs = aws_source.get_endpoints(options)
    elb_map = {}
    for elb in elbs:
        elb_map[elb["name"]] = elb
    assert elb_map["example-lb"]["certificate_name"] == cert_name1
    assert elb_map["example-lb"]["registry_type"] == "acm"
    assert elb_map["example-lb"]["port"] == 443
    assert elb_map["test-lbv2"]["certificate_name"] == cert_name2
    assert elb_map["test-lbv2"]["registry_type"] == "acm"
    assert elb_map["test-lbv2"]["port"] == 1443
