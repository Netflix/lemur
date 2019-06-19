"""
.. module: lemur.plugins.lemur_aws.s3
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS S3 Apis.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from .sts import sts_client


@sts_client("s3", service_type="resource")
def put(bucket_name, region, prefix, data, encrypt, **kwargs):
    """
    Use STS to write to an S3 bucket
    """
    bucket = kwargs["resource"].Bucket(bucket_name)
    current_app.logger.debug(
        "Persisting data to S3. Bucket: {0} Prefix: {1}".format(bucket_name, prefix)
    )

    # get data ready for writing
    if isinstance(data, str):
        data = data.encode("utf-8")

    if encrypt:
        bucket.put_object(
            Key=prefix,
            Body=data,
            ACL="bucket-owner-full-control",
            ServerSideEncryption="AES256",
        )
    else:
        bucket.put_object(Key=prefix, Body=data, ACL="bucket-owner-full-control")
