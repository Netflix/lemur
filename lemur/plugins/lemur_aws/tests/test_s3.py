from moto import mock_s3
import boto


@mock_s3()
def test_get_name_from_arn():
    conn = boto.connect_s3()
    conn.create_bucket('test')
    from lemur.plugins.lemur_aws.s3 import write_to_s3
    write_to_s3('11111111111111', 'test', 'key', 'body')
    assert conn.get_bucket('test').get_key('key').get_contents_as_string() == 'body'
