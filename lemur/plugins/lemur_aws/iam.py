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
        account_number=account_number, certificate_name=certificate_name
    )


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
    else:
        name = name + "-" + path.strip("/")

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
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def get_certificate(name, **kwargs):
    """
    Retrieves an SSL certificate.

    :return:
    """
    client = kwargs.pop("client")
    metrics.send("get_certificate", "counter", 1, metric_tags={"name": name})
    try:
        return client.get_server_certificate(ServerCertificateName=name)["ServerCertificate"]
    except client.exceptions.NoSuchEntityException:
        capture_exception()
        return None


@sts_client("iam")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def get_certificates(**kwargs):
    """
    Fetches one page of certificate objects for a given account.
    :param kwargs:
    :return:
    """
    client = kwargs.pop("client")
    metrics.send("get_certificates", "counter", 1)
    return client.list_server_certificates(**kwargs)


def get_all_certificates(**kwargs):
    """
    Use STS to fetch all of the SSL certificates from a given account
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
        response = get_certificates(**kwargs)
        metadata = response["ServerCertificateMetadataList"]

        for m in metadata:
            certificates.append(
                get_certificate(
                    m["ServerCertificateName"], account_number=account_number
                )
            )

        if not response.get("Marker"):
            return certificates
        else:
            kwargs.update(dict(Marker=response["Marker"]))
