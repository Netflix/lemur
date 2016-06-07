"""
.. module: lemur.plugins.lemur_aws.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from boto.exception import BotoServerError

from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam
from lemur.plugins.lemur_aws.ec2 import get_regions
from lemur.plugins.lemur_aws.elb import get_all_elbs, describe_load_balancer_policies, attach_certificate
from lemur.plugins import lemur_aws as aws


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
                iam.upload_cert(self.get_option('accountNumber', options), name, body, private_key, cert_chain=cert_chain)
            except BotoServerError as e:
                if e.error_code != 'EntityAlreadyExists':
                    raise Exception(e)

            e = self.get_option('elb', options)
            if e:
                attach_certificate(kwargs['accountNumber'], ['region'], e['name'], e['port'], e['certificateId'])
        else:
            raise Exception("Unable to upload to AWS, private key is required")


class AWSSourcePlugin(SourcePlugin):
    title = 'AWS'
    slug = 'aws-source'
    description = 'Discovers all SSL certificates and ELB endpoints in an AWS account'
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
            'name': 'regions',
            'type': 'str',
            'helpMessage': 'Comma separated list of regions to search in, if no region is specified we look in all regions.'
        },
    ]

    def get_certificates(self, options, **kwargs):
        certs = []
        arns = iam.get_all_server_certs(self.get_option('accountNumber', options))
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

    def get_endpoints(self, options, **kwargs):
        endpoints = []
        account_number = self.get_option('accountNumber', options)
        regions = self.get_option('regions', options)

        if not regions:
            regions = get_regions(account_number=account_number)
        else:
            regions = regions.split(',')

        for region in regions:
            elbs = get_all_elbs(account_number=account_number, region=region)
            current_app.logger.info("Describing load balancers in {0}-{1}".format(account_number, region))
            for elb in elbs['LoadBalancerDescriptions']:
                for listener in elb['ListenerDescriptions']:
                    if not listener['Listener'].get('SSLCertificateId'):
                        continue

                    endpoint = dict(
                        name=elb['LoadBalancerName'],
                        dnsname=elb['DNSName'],
                        type='elb',
                        port=listener['Listener']['LoadBalancerPort'],
                        certificate_name=iam.get_name_from_arn(listener['Listener']['SSLCertificateId'])
                    )

                    if listener['PolicyNames']:
                        policy = describe_load_balancer_policies(elb['LoadBalancerName'], listener['PolicyNames'], account_number=account_number, region=region)
                        endpoint['policy'] = format_elb_cipher_policy(policy)

                    endpoints.append(endpoint)

        return endpoints


def format_elb_cipher_policy(policy):
    """
    Attempts to format cipher policy information into a common format.
    :param policy:
    :return:
    """
    ciphers = []
    name = None
    for descr in policy['PolicyDescriptions']:
        for attr in descr['PolicyAttributeDescriptions']:
            if attr['AttributeName'] == 'Reference-Security-Policy':
                name = attr['AttributeValue']
                continue

            if attr['AttributeValue'] == 'true':
                ciphers.append(attr['AttributeName'])

    return dict(name=name, ciphers=ciphers)
