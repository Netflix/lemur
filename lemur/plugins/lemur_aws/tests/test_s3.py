import boto3
from moto import mock_sts, mock_s3


@mock_sts()
@mock_s3()
def test_put_delete_s3_object(app):
    from lemur.plugins.lemur_aws.s3 import put, delete, get

    bucket = "public-bucket"
    account = "123456789012"
    path = "some-path/foo"
    data = "dummy data"

    s3_client = boto3.client('s3')
    s3_client.create_bucket(Bucket=bucket)

    put(bucket_name=bucket,
        region=None,
        prefix=path,
        data=data,
        encrypt=False,
        account_number=account)

    response = get(bucket_name=bucket, prefix=path, account_number=account)

    # put data, and getting the same data
    assert (response == data)

    response = get(bucket_name="wrong-bucket", prefix=path, account_number=account)

    # attempting to get thccle wrong data
    assert (response is None)

    delete(bucket_name=bucket, prefix=path, account_number=account)
    response = get(bucket_name=bucket, prefix=path, account_number=account)

    # delete data, and getting the same data
    assert (response is None)
