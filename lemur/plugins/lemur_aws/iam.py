"""
.. module: lemur.plugins.lemur_aws.iam
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS IAM Apis.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import botocore

from retrying import retry
from sentry_sdk import capture_exception

from lemur.extensions import metrics
from lemur.plugins.lemur_aws.sts import sts_client


def retry_throttled(exception):
    """
    Determines if this exception is due to throttling
    :param exception:
    :return:
    """
    if isinstance(exception, botocore.exceptions.ClientError):
        if exception.response["Error"]["Code"] == "NoSuchEntity":
            return False

        # No need to retry deletion requests if there is a DeleteConflict error.
        # This error indicates that the certificate is still attached to an entity
        # and cannot be deleted.
        if exception.response["Error"]["Code"] == "DeleteConflict":
            return False

    metrics.send("iam_retry", "counter", 1, metric_tags={"exception": str(exception)})
    return True


def get_name_from_arn(arn):
    """
    Extract the certificate name from an arn.

    examples:
    'arn:aws:iam::123456789012:server-certificate/example.com'  -->  'example.com'
    'arn:aws:iam::123456789012:server-certificate/cloudfront/example.com-cloudfront' --> 'example.com-cloudfront'
    'arn:aws:acm:us-west-2:123456789012:certificate/example.com' --> 'example.com'

    :param arn: IAM TLS certificate arn
    :return: name of the certificate as uploaded to AWS
    """
    return arn.split("/")[-1]


def get_path_from_arn(arn):
    """
    Get the certificate path from the certificate arn.

    examples:
    'arn:aws:iam::123456789012:server-certificate/example.com'   -->  ''
    'arn:aws:iam::123456789012:server-certificate/cloudfront/example.com-cloudfront'  -->  'cloudfront'
    'arn:aws:iam::123456789012:server-certificate/cloudfront/2/example.com-cloudfront'  -->  'cloudfront/2'
    'arn:aws:acm:us-west-2:123456789012:certificate/example.com'  -->  ''

    :param arn: IAM TLS certificate arn
    :return: empty or the certificate path without the certificate name
    """
    # cloudfront/example.com-cloudfront
    file_path = arn.split("/", 1)[1]
    if '/' in file_path:
        # remove the filename, and return the path
        return '/'.join(file_path.split("/")[:-1])
    else:
        return ''


def get_registry_type_from_arn(arn):
    """
    Get the registery type based on the arn.

    examples:
    'arn:aws:iam::123456789000:server-certificate/example.com'  -->  'iam'
    'arn:aws:iam::123456789000:server-certificate/cloudfront/example.com-cloudfront'  --> 'iam'
    'arn:aws:acm:us-west-2:123456789000:certificate/example.com'  -->  'acm'

    :param arn: IAM TLS certificate arn
    :return: iam or acm or unkown
    """
    if arn.startswith("arn:aws:iam") or arn.startswith("arn:aws-us-gov:iam") or arn.startswith("arn:aws-cn:iam"):
        return 'iam'
    elif arn.startswith("arn:aws:acm") or arn.startswith("arn:aws-us-gov:acm") or arn.startswith("arn:aws-cn:acm"):
        return 'acm'
    else:
        return 'unknown'


def create_arn_from_cert(account_number, partition, certificate_name, path=''):
    """
    Create an ARN from a certificate.
    :param path:
    :param account_number:
    :param partition:
    :param certificate_name:
    :return:
    """
    if path is None or path == '':
        return f"arn:{partition}:iam::{account_number}:server-certificate/{certificate_name}"
    else:
        return f"arn:{partition}:iam::{account_number}:server-certificate/{path}/{certificate_name}"


@sts_client("iam")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def upload_cert(name, body, private_key, path, cert_chain=None, **kwargs):
    """
    Upload a certificate to AWS

    :param name:
    :param body:
    :param private_key:
    :param cert_chain:
    :param path:
    :return:
    """
    assert isinstance(private_key, str)
    client = kwargs.pop("client")

    if not path or path == "/":
        path = "/"

    metrics.send("upload_cert", "counter", 1, metric_tags={"name": name, "path": path})
    try:
        if cert_chain:
            return client.upload_server_certificate(
                Path=path,
                ServerCertificateName=name,
                CertificateBody=str(body),
                PrivateKey=str(private_key),
                CertificateChain=str(cert_chain),
            )
        else:
            return client.upload_server_certificate(
                Path=path,
                ServerCertificateName=name,
                CertificateBody=str(body),
                PrivateKey=str(private_key),
            )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise e


@sts_client("iam")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def delete_cert(cert_name, **kwargs):
    """
    Delete a certificate from AWS

    :param cert_name:
    :return:
    """
    client = kwargs.pop("client")
    metrics.send("delete_cert", "counter", 1, metric_tags={"cert_name": cert_name})
    try:
        client.delete_server_certificate(ServerCertificateName=cert_name)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise e


@sts_client("iam")
def get_certificate(name, **kwargs):
    """
    Retrieves an SSL certificate.

    :return:
    """
    return _get_certificate(name, **kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificate(name, **kwargs):
    metrics.send("get_certificate", "counter", 1, metric_tags={"name": name})
    client = kwargs.pop("client")
    try:
        return client.get_server_certificate(ServerCertificateName=name)["ServerCertificate"]
    except client.exceptions.NoSuchEntityException:
        capture_exception()
        return None


@sts_client("iam")
def get_certificates(**kwargs):
    """
    Fetches one page of certificate objects for a given account.
    :param kwargs:
    :return:
    """
    return _get_certificates(**kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificates(**kwargs):
    metrics.send("get_certificates", "counter", 1)
    return kwargs.pop("client").list_server_certificates(**kwargs)


@sts_client("iam")
def get_all_certificates(restrict_path=None, **kwargs):
    """
    Use STS to fetch all of the SSL certificates from a given account
    :param restrict_path: If provided, only return certificates with a matching Path value.
    """
    certificates = []
    account_number = kwargs.get("account_number")
    metrics.send(
        "get_all_certificates",
        "counter",
        1,
        metric_tags={"account_number": account_number},
    )

    while True:
        response = _get_certificates(**kwargs)
        metadata = response["ServerCertificateMetadataList"]

        for m in metadata:
            if restrict_path and m["Path"] != restrict_path:
                continue
            certificates.append(
                _get_certificate(
                    m["ServerCertificateName"],
                    client=kwargs["client"]
                )
            )

        if not response.get("Marker"):
            return certificates
        else:
            kwargs.update(dict(Marker=response["Marker"]))


def get_certificate_id_to_name(**kwargs):
    """
    Use STS to fetch a map of IAM certificate IDs to names
    """
    id_to_name = {}
    account_number = kwargs.get("account_number")
    metrics.send(
        "get_certificate_id_to_name",
        "counter",
        1,
        metric_tags={"account_number": account_number},
    )

    while True:
        response = get_certificates(**kwargs)
        metadata = response["ServerCertificateMetadataList"]

        for m in metadata:
            id_to_name[m["ServerCertificateId"]] = m["ServerCertificateName"]

        if not response.get("Marker"):
            return id_to_name
        else:
            kwargs.update(dict(Marker=response["Marker"]))
