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

from lemur.extensions import metrics
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

    metrics.send('iam_retry', 'counter', 1)
    return True


def get_name_from_arn(arn):
    """
    Extract the certificate name from an arn.

    :param arn: IAM SSL arn
    :return: name of the certificate as uploaded to AWS
    """
    return arn.split("/", 1)[1]


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


@sts_client('iam')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=100)
def upload_cert(name, body, private_key, cert_chain=None, **kwargs):
    """
    Upload a certificate to AWS

    :param name:
    :param body:
    :param private_key:
    :param cert_chain:
    :return:
    """
    client = kwargs.pop('client')
    try:
        if cert_chain:
            return client.upload_server_certificate(
                ServerCertificateName=name,
                CertificateBody=str(body),
                PrivateKey=str(private_key),
                CertificateChain=str(cert_chain)
            )
        else:
            return client.upload_server_certificate(
                ServerCertificateName=name,
                CertificateBody=str(body),
                PrivateKey=str(private_key)
            )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] != 'EntityAlreadyExists':
            raise e


@sts_client('iam')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=100)
def delete_cert(cert_name, **kwargs):
    """
    Delete a certificate from AWS

    :param cert_name:
    :return:
    """
    client = kwargs.pop('client')
    client.delete_server_certificate(ServerCertificateName=cert_name)


@sts_client('iam')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=100)
def get_certificate(name, **kwargs):
    """
    Retrieves an SSL certificate.

    :return:
    """
    client = kwargs.pop('client')
    return client.get_server_certificate(
        ServerCertificateName=name
    )['ServerCertificate']


@sts_client('iam')
@retry(retry_on_exception=retry_throttled, stop_max_attempt_number=7, wait_exponential_multiplier=100)
def get_certificates(**kwargs):
    """
    Fetches one page of certificate objects for a given account.
    :param kwargs:
    :return:
    """
    client = kwargs.pop('client')
    return client.list_server_certificates(**kwargs)


def get_all_certificates(**kwargs):
    """
    Use STS to fetch all of the SSL certificates from a given account
    """
    certificates = []
    account_number = kwargs.get('account_number')

    while True:
        response = get_certificates(**kwargs)
        metadata = response['ServerCertificateMetadataList']

        for m in metadata:
            certificates.append(get_certificate(m['ServerCertificateName'], account_number=account_number))

        if not response.get('Marker'):
            return certificates
        else:
            kwargs.update(dict(Marker=response['Marker']))
