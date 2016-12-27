"""
.. module: lemur.plugins.lemur_aws.iam
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS IAM Apis.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import botocore

from retrying import retry

from lemur.plugins.lemur_aws.sts import assume_service
from lemur.plugins.lemur_aws.sts import sts_client


def retry_throttled(exception):
    """
    Determines if this exception is due to throttling
    :param exception:
    :return:
    """
    if isinstance(exception, botocore.exceptions.ClientError):
        if exception.response['Error']['Code'] == 'NoSuchEntity':
            return False
    return True


def get_name_from_arn(arn):
    """
    Extract the certificate name from an arn.

    :param arn: IAM SSL arn
    :return: name of the certificate as uploaded to AWS
    """
    return arn.split("/", 1)[1]


def upload_cert(account_number, name, body, private_key, cert_chain=None):
    """
    Upload a certificate to AWS

    :param account_number:
    :param name:
    :param private_key:
    :param cert_chain:
    :return:
    """
    return assume_service(account_number, 'iam').upload_server_cert(name, str(body), str(private_key),
                                                                    cert_chain=str(cert_chain))


@sts_client('iam')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=1000)
def delete_cert(cert_name, **kwargs):
    """
    Delete a certificate from AWS

    :param cert_name:
    :return:
    """
    client = kwargs.pop('client')
    client.delete_server_certificate(ServerCertificateName=cert_name)


def get_all_server_certs(account_number):
    """
    Use STS to fetch all of the SSL certificates from a given account

    :param account_number:
    """
    marker = None
    certs = []
    while True:
        response = assume_service(account_number, 'iam').get_all_server_certs(marker=marker)
        result = response['list_server_certificates_response']['list_server_certificates_result']

        for cert in result['server_certificate_metadata_list']:
            certs.append(cert['arn'])

        if result['is_truncated'] == 'true':
            marker = result['marker']
        else:
            return certs


def get_cert_from_arn(arn):
    """
    Retrieves an SSL certificate from a given ARN.

    :param arn:
    :return:
    """
    name = get_name_from_arn(arn)
    account_number = arn.split(":")[4]
    name = name.split("/")[-1]

    response = assume_service(account_number, 'iam').get_server_certificate(name.strip())
    return digest_aws_cert_response(response)


def create_arn_from_cert(account_number, region, certificate_name):
    """
    Create an ARN from a certificate.
    :param account_number:
    :param region:
    :param certificate_name:
    :return:
    """
    return "arn:aws:iam::{account_number}:server-certificate/{certificate_name}".format(
        account_number=account_number,
        certificate_name=certificate_name)


def digest_aws_cert_response(response):
    """
    Processes an AWS certifcate response and retrieves the certificate body and chain.

    :param response:
    :return:
    """
    chain = None
    cert = response['get_server_certificate_response']['get_server_certificate_result']['server_certificate']
    body = cert['certificate_body']

    if 'certificate_chain' in cert:
        chain = cert['certificate_chain']

    return body, chain
