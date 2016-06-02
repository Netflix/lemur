"""
.. module: lemur.plugins.lemur_aws.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from boto.exception import BotoServerError

from sslyze.plugins_process_pool import PluginsProcessPool
from sslyze.plugins_finder import PluginsFinder
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.ssl_settings import TlsWrappedProtocolEnum

from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam
from lemur.plugins.lemur_aws.elb import get_all_elbs, describe_load_balancer_policies, attach_certificate
from lemur.plugins.lemur_aws.ec2 import get_all_instances
from lemur.plugins import lemur_aws as aws


def is_available(hostname, port):
    """
    Determine if a given endpoint is reachable

    :param hostname:
    :param port:
    :return:
    """
    try:
        server_info = ServerConnectivityInfo(hostname=hostname, port=port,
                                             tls_wrapped_protocol=TlsWrappedProtocolEnum.PLAIN_TLS)
        server_info.test_connectivity_to_server()
        return server_info
    except Exception as e:
        current_app.logger.error('Error when connecting to {}:{} Reason: {}'.format(hostname, port, e))


def get_endpoint_data(server_info):
    # Get the list of available plugins
    sslyze_plugins = PluginsFinder()

    # Create a process pool to run scanning commands concurrently
    plugins_process_pool = PluginsProcessPool(sslyze_plugins)

    # Queue a scan command to get the server's certificate
    plugins_process_pool.queue_plugin_task(server_info, 'sslv3')
    plugins_process_pool.queue_plugin_task(server_info, 'certinfo_basic')
    plugins_process_pool.queue_plugin_task(server_info, 'tlsv1')
    plugins_process_pool.queue_plugin_task(server_info, 'tlsv1_1')
    plugins_process_pool.queue_plugin_task(server_info, 'tlsv1_2')

    # Process the result and print the certificate CN
    data = {'ciphers': [], 'certificate': {}}
    for plugin_result in plugins_process_pool.get_results():
        if plugin_result.plugin_command == 'certinfo_basic':
            data['certificate'] = {
                'body': plugin_result.certificate_chain[0].as_pem,
                'chain': "\n".join([x.as_pem for x in plugin_result.certificate_chain[1:]])
            }
        else:
            for cipher in plugin_result.accepted_cipher_list:
                data['ciphers'].append({'name': cipher.name, 'value': True})
    return data


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
        {
            'name': 'instances',
            'type': 'bool',
            'helpMessage': 'By default we search IAM and ELBs for certificates and endpoints, with instances selected we also attempt to connect indivdual instances to collect endpoint information. This could take a very long time depending on the number of instances.'
        },
        {
            'name': 'securePorts',
            'type': 'str',
            'helpMessage': 'Ports to extract endpoint information from, used when "instances" is enabled'
        }
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
        for region in self.get_option('regions', options).split(','):
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

            if self.get_option('instances', options):
                current_app.logger.info("Describing ec2 instances in {0}-{1}".format(account_number, region))
                secure_ports = [int(x) for x in self.get_option('securePorts', options).split(',')]
                pages = get_all_instances(account_number=account_number, region=region)
                for page in pages:
                    for reservation in page['Reservations']:
                        for instance in reservation['Instances']:
                            hostname = instance['PrivateDnsName']
                            for port in secure_ports:
                                #  attempt sslyze on common ports
                                server_info = is_available(hostname, port)

                                if not server_info:
                                    continue

                                endpoint = get_endpoint_data(server_info)

                                if endpoint:
                                    endpoints.append(dict(
                                        dnsname=hostname,
                                        port=port,
                                        type='instance',
                                        certificate=endpoint['certificate'],
                                        policy=endpoint['cipher']
                                    ))

        return endpoints


def format_elb_cipher_policy(policy):
    """
    Attempts to format cipher policy information into a common format.
    :param policy:
    :return:
    """
    lemur_policy = {'ciphers': []}
    for descr in policy['PolicyDescriptions']:
        lemur_policy['name'] = descr['PolicyName']
        for attr in descr['PolicyAttributeDescriptions']:
            if attr['AttributeValue'] == 'true':
                value = True
            elif attr['AttributeValue'] == 'false':
                value = False
            else:
                continue

            cipher = {'name': attr['AttributeName'], 'value': value}
            lemur_policy['ciphers'].append(cipher)
    return lemur_policy
