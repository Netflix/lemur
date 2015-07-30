"""
.. module: lemur.plugins.lemur_aws.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam, elb
from lemur.plugins import lemur_aws as aws


def find_value(name, options):
    for o in options:
        if o.get(name):
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
            'type': 'int',
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

    def upload(self, cert, private_key, cert_chain, options, **kwargs):
        iam.upload_cert(find_value('accountNumber', options), cert, private_key, cert_chain=cert_chain)

        e = find_value('elb', options)
        if e:
            elb.attach_certificate(kwargs['accountNumber'], ['region'], e['name'], e['port'], e['certificateId'])


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
        {
            'name': 'pollRate',
            'type': 'int',
            'required': False,
            'helpMessage': 'Rate in seconds to poll source for new information.',
            'default': '60',
        }
    ]

    def get_certificates(self, **kwargs):
        certs = []
        arns = elb.get_all_server_certs(kwargs['account_number'])
        for arn in arns:
            cert_body = iam.get_cert_from_arn(arn)
            cert_name = iam.get_name_from_arn(arn)
            cert = dict(
                public_certificate=cert_body,
                name=cert_name
            )
            certs.append(cert)
        return certs
