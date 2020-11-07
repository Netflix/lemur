import boto3
from moto import mock_sts, mock_s3


def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-s3")
    assert p


@mock_sts()
@mock_s3()
def test_upload_acme_token(app):
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
            "validation": r"[0-9a-z.-]{3,63}",
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "value": account,
            "required": True,
            "validation": r"[0-9]{12}",
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

    p.upload_acme_token(token_path=token_path,
                        token_content=token_content,
                        token=token_content,
                        options=additional_options)

    response = get(bucket_name=bucket,
                   prefixed_object_name=prefix + token_name,
                   encrypt=False,
                   account_number=account)

    # put data, and getting the same data
    assert (response == token_content)
