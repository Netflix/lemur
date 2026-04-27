"""
.. module: lemur.plugins.lemur_aws.acm
    :platform: Unix
    :synopsis: Contains helper functions for interactive with AWS ACM Apis.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Pinmarva <pinmarva@gmail.com>
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

    metrics.send("acm_retry", "counter", 1, metric_tags={"exception": str(exception)})
    return True


def get_id_from_arn(arn):
    """
    Extract the certificate name from an arn.

    examples:
    'arn:aws:acm:us-west-2:123456789012:certificate/1aa111a1-1a11-1111-11aa-a11aa111aa11' '1aa111a1-1a11-1111-11aa-a11aa111aa11'

    :param arn: ACM TLS certificate arn
    :return: id of the certificate as uploaded to AWS
    """
    return arn.split("/")[-1]


@sts_client("acm")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def upload_cert(name, body, private_key, cert_chain=None, **kwargs):
    """
    Upload a certificate to ACM AWS

    :param body:
    :param private_key:
    :param cert_chain:
    :param path:
    :return:
    """
    assert isinstance(private_key, str)
    client = kwargs.pop("client")

    metrics.send("upload_acm_cert", "counter", 1, metric_tags={"name": name})
    try:
        if cert_chain:
            return client.import_certificate(
                Certificate=str(body),
                PrivateKey=str(private_key),
                CertificateChain=str(cert_chain),
            )
        else:
            return client.import_certificate(
                Certificate=str(body),
                PrivateKey=str(private_key),
            )
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise e


@sts_client("acm")
@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def delete_cert(cert_arn, **kwargs):
    """
    Delete a certificate from ACM AWS

    :param cert_arn:
    :return:
    """
    client = kwargs.pop("client")
    metrics.send("delete_acm_cert", "counter", 1, metric_tags={"cert_arn": cert_arn})
    try:
        client.delete_certificate(CertificateArn=cert_arn)
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise e


@sts_client("acm")
def get_certificate(name, **kwargs):
    """
    Retrieves an acm SSL certificate.

    :return:
    """
    return _get_certificate(name, **kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificate(arn, **kwargs):
    metrics.send("get_acm_certificate", "counter", 1, metric_tags={"arn": arn})
    client = kwargs.pop("client")
    try:
        return client.get_certificate(CertificateArn=arn)
    except client.exceptions.NoSuchEntityException:
        capture_exception()
        return None


@sts_client("acm")
def get_certificates(**kwargs):
    """
    Fetches one page of acm certificate objects for a given account.
    :param kwargs:
    :return:
    """
    return _get_certificates(**kwargs)


@retry(retry_on_exception=retry_throttled, wait_fixed=2000, stop_max_attempt_number=25)
def _get_certificates(**kwargs):
    metrics.send("get_acm_certificates", "counter", 1)
    return kwargs.pop("client").list_certificates(
        **kwargs,
        CertificateStatuses=[
            'ISSUED'
        ]
    )


@sts_client("acm")
def get_all_certificates(**kwargs):
    """
    Use STS to fetch all of the ACM SSL certificates from a given account
    :param restrict_path: If provided, only return certificates with a matching Path value.
    """
    certificates = []
    account_number = kwargs.get("account_number")
    metrics.send(
        "get_all_acm_certificates",
        "counter",
        1,
        metric_tags={"account_number": account_number},
    )

    while True:
        response = _get_certificates(**kwargs)
        metadata = response["CertificateSummaryList"]

        for m in metadata:
            certificate = _get_certificate(
                m["CertificateArn"],
                client=kwargs["client"]
            )

            if certificate is None:
                continue

            certificate.update(
                name=m["DomainName"],
                external_id=m["CertificateArn"]
            )
            certificates.append(certificate)

        if not response.get("Marker"):
            return certificates
        else:
            kwargs.update(dict(Marker=response["Marker"]))
