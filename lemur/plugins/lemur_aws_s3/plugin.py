"""
.. module: lemur.plugins.lemur_kubernetes.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>


    The plugin allows to use a secure S3 bucket as Lemur destination.

    Terraform example to setup the destination bucket:
    resource "aws_s3_bucket" "certs_log_bucket" {
         bucket = "certs-log-access-bucket"
        acl    = "log-delivery-write"
    }

    resource "aws_s3_bucket" "certs_lemur" {
        bucket = "certs-lemur"
        acl    = "private"

      logging {
        target_bucket = "${aws_s3_bucket.certs_log_bucket.id}"
        target_prefix = "log/lemur"
      }
    }


    The IAM role Lemur is running as should have the following actions on the destination bucket:

    "S3:PutObject",
    "S3:PutObjectAcl"


    The reader should have the following actions:
    "s3:GetObject"



"""
import base64

from lemur.plugins.bases import DestinationPlugin
import boto
from boto.s3.key import Key


def ensure_certificate(bucket, key, body):
    conn = boto.connect_s3()
    b = conn.get_bucket(bucket, validate=False)  # validate=False removes need for ListObjects permission
    k = Key(bucket=b, name=key)
    k.set_contents_from_string(body, encrypt_key=True)
    k.set_canned_acl("bucket-owner-read")


class S3DestinationPlugin(DestinationPlugin):
    title = 'AWS-S3'
    slug = 'aws-s3'
    description = 'Allow the uploading of certificates to Amazon S3'

    author = 'Mikhail Khodorovskiy'
    author_url = 'https://github.com/mik373/lemur'

    options = [
        {
            'name': 'bucket',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid S3 bucket name!',
        },
        {
            'name': 'key',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid S3 object key!',
        },
        {
            'name': 'caKey',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid S3 object key!',
        },
        {
            'name': 'certKey',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid S3 object key!',
        }
    ]

    def __init__(self, *args, **kwargs):
        super(S3DestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        s3_bucket = self.get_option('bucket', options)
        s3_key = self.get_option('key', options)
        s3_cakey = self.get_option('caKey', options)
        s3_certkey = self.get_option('certKey', options)

        key_body = base64.b64encode(private_key)
        cert_body = base64.b64encode(body)
        ca_body = base64.b64encode(cert_chain)

        ensure_certificate(s3_bucket, s3_key, key_body)
        ensure_certificate(s3_bucket, s3_cakey, ca_body)
        ensure_certificate(s3_bucket, s3_certkey, cert_body)


if __name__ == "__main__":
    ensure_certificate('lemurtest2', 'olo', "Seth")



