"""
.. module: lemur.plugins.lemur_aws.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from boto.exception import BotoServerError
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam, elb
from lemur.plugins import lemur_aws as aws


def find_value(name, options):
    for o in options:
        if o['name'] == name:
            return o['value']


class AWSDestinationPlugin(DestinationPlugin):
    title = 'AWS'
    slug = 'aws-destination'
    description = 'Allow the uploading of certificates to AWS IAM'
    version = aws.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    options = [
        {
            'name': 'accountNumber',
            'type': 'str',
            'required': True,
            'validation': '/^[0-9]{12,12}$/',
            'helpMessage': 'Must be a valid AWS account number!',
        }
    ]
    # 'elb': {
    #    'name': {'type': 'name'},
    #    'region': {'type': 'str'},
    #    'port': {'type': 'int'}
    # }

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        if private_key:
            try:
                iam.upload_cert(find_value('accountNumber', options), name, body, private_key, cert_chain=cert_chain)
            except BotoServerError as e:
                if e.error_code != 'EntityAlreadyExists':
                    raise Exception(e)

            e = find_value('elb', options)
            if e:
                elb.attach_certificate(kwargs['accountNumber'], ['region'], e['name'], e['port'], e['certificateId'])
        else:
            raise Exception("Unable to upload to AWS, private key is required")


class AWSSourcePlugin(SourcePlugin):
    title = 'AWS'
    slug = 'aws-source'
    description = 'Discovers all SSL certificates in an AWS account'
    version = aws.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    options = [
        {
            'name': 'accountNumber',
            'type': 'str',
            'required': True,
            'validation': '/^[0-9]{12,12}$/',
            'helpMessage': 'Must be a valid AWS account number!',
        },
    ]

    def get_certificates(self, options, **kwargs):
        certs = []
        arns = iam.get_all_server_certs(find_value('accountNumber', options))
        for arn in arns:
            cert_body, cert_chain = iam.get_cert_from_arn(arn)
            cert_name = iam.get_name_from_arn(arn)
            cert = dict(
                body=cert_body,
                chain=cert_chain,
                name=cert_name
            )
            certs.append(cert)
        return certs
