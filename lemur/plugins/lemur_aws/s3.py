"""
.. module: lemur.plugins.lemur_aws.s3
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS S3 Apis.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from boto.s3.key import Key
from lemur.plugins.lemur_aws.sts import assume_service


def put(account_number, bucket_name, key, data, encrypt):
    """
    Use STS to write to an S3 bucket

    :param account_number:
    :param bucket_name:
    :param data:
    """
    conn = assume_service(account_number, 's3')
    b = conn.get_bucket(bucket_name, validate=False)  # validate=False removes need for ListObjects permission

    k = Key(bucket=b, name=key)
    k.set_contents_from_string(data, encrypt_key=encrypt)
    k.set_canned_acl("bucket-owner-read")
