"""
.. module: lemur.plugins.lemur_s3
    :platform: Unix
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Harm Weites <harm@weites.com>
"""
import os
import tempfile
from boto.exception import S3CreateError
from boto.s3.key import Key
from flask import current_app
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins import lemur_s3 as s3
from lemur.plugins.lemur_aws.sts import assume_service


def find_value(name, options):
    for o in options:
        if o['name'] == name:
            return o['value']


class S3DestinationPlugin(DestinationPlugin):
    title = 'S3'
    slug = 's3-destination'
    description = 'Allows uploading certificates to Amazon S3'
    version = s3.VERSION

    author = 'Harm Weites'
    author_url = 'https://github.com/netflix/lemur'

    options = [
        {
            'name': 'accountNumber',
            'type': 'int',
            'required': True,
            'validation': '/^[0-9]{12,12}$/',
            'helpMessage': 'A valid AWS account number with permission to access S3',
        }, {
            'name': 'bucket',
            'type': 'str',
            'default': 'certificate-store',
            'required': True,
            'validation': '/^\w+$/',
            'helpMessage': 'The name of your bucket',
        }, {
            'name': 'region',
            'type': 'str',
            'default': 'eu-west-1',
            'required': False,
            'validation': '/^\w+-\w+-\d+$/',
            'helpMessage': 'Availability zone to use',
        }
    ]

    """
    Outputs the certificate data to a local file and returns its name.
    """
    def createPemFile(self, cert, key, chain):
        tmpfile = tempfile.NamedTemporaryFile(dir='/tmp/', prefix='_tmp', delete=False)
        current_app.logger.debug('PEM file created as %s' % tmpfile.name)
        os.chmod(tmpfile.name, 0o600)

        with tmpfile.file as pem:
            pem.write(key + '\n' + cert + '\n' + chain + '\n')

        return tmpfile.name

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        current_app.logger.info("Preparing to upload %s to S3" % name)

        if private_key:
            try:
                pemfile = self.createPemFile(body, private_key, cert_chain)
            except Exception as error:
                current_app.logger.error(error)
                raise

            bucket_name = find_value('bucket', options)
            try:
                conn = assume_service(find_value('accountNumber', options), 's3', find_value('region', options))
            except Exception as error:
                current_app.logger.error("Could not connect to S3 for bucket %s: %s" % (bucket_name, error))
                raise

            if conn is None:
                current_app.logger.error("Failed to connect to AWS")
                raise

            bucket = conn.lookup(bucket_name)
            if bucket is None:
                try:
                    bucket = conn.create_bucket(bucket_name, location=find_value('region', options))
                except S3CreateError as err:
                    current_app.logger.error("Failed to create bucket %s in region %s: %s" % (bucket_name, find_value('region', options), err))
                raise

            current_app.logger.debug("Connected to S3 bucket %s in region %s" % (bucket_name, find_value('region', options)))

            k = Key(bucket)
            k.key = name + '.pem'
            try:
                k.set_contents_from_filename(pemfile, replace=True, encrypt_key=True)
            except Exception as error:
                current_app.logger.error("Uploading PEM file failed: %s" % error)
                raise

            current_app.logger.info("Uploading of %s to S3 bucket %s was succesful" % (name, bucket_name))

            try:
                os.remove(pemfile)
            except Exception as error:
                current_app.logger.error("Removing local file failed with: %s" % error)
                raise

        else:
            raise Exception("Unable to create PEM file, private key is required")
