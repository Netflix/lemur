"""
.. module: lemur.plugins.lemur_aws.cloudfront
    :synopsis: Helper code for discovering CloudFront endpoints

.. moduleauthor:: <lemur@netflix.com>
"""

from flask import current_app
from sentry_sdk import capture_exception

from lemur.exceptions import InvalidDistribution
from lemur.extensions import metrics
from lemur.plugins.lemur_aws.sts import sts_client


def get_all_distributions(**kwargs):
    """
    Fetches all distributions for a given account/region
    :param kwargs:
        account_number: AWS account number
    :return:
    """
    distributions = []
    try:
        while True:
            response = get_distributions(**kwargs)

            list = response.get("DistributionList")
            if not list:
                return distributions

            items = list.get("Items")
            if not items:
                return distributions
            distributions += items

            if not list.get("IsTruncated"):
                return distributions
            else:
                kwargs.update(dict(Marker=list["NextMarker"]))
    except Exception as e:  # noqa
        metrics.send("list_all_distributions_error", "counter", 1)
        capture_exception()
        raise


@sts_client("cloudfront")
def get_distributions(**kwargs):
    """
    Fetches one page CloudFront distribution objects for a given account and region.
    :param kwargs:
        account_number: AWS account number
    :return:
    """
    try:
        client = kwargs.pop("client")
        return client.list_distributions(**kwargs)
    except Exception as e:  # noqa
        metrics.send("list_distributions_error", "counter", 1, metric_tags={"error": str(e)})
        capture_exception()
        raise


@sts_client("cloudfront")
def get_distribution(distribution_id, **kwargs):
    """
    Fetches a single distribution by ID
    :param distribution_id: The Id of a distribution
    :param kwargs:
        account_number: AWS account number
    :return:
    """
    try:
        dist_and_config = kwargs["client"].get_distribution(Id=distribution_id)["Distribution"]
        # Compose a similar dictionary to get_all_distributions
        dist = {
            "Id": dist_and_config["Id"],
            "ARN": dist_and_config["ARN"],
            "Status": dist_and_config["Status"],
            "DomainName": dist_and_config["DomainName"],
            "AliasICPRecordals": dist_and_config.get("AliasICPRecordals"),
        }
        dist.update(dist_and_config["DistributionConfig"])
        return dist
    except Exception as e:  # noqa
        metrics.send("get_distribution_error", "counter", 1)
        capture_exception()
        raise


@sts_client("cloudfront")
def attach_certificate(distribution_id, iam_cert_id, **kwargs):
    """
    Updates the IAM certificate associated with a distribution
    :param distribution_id: The Id of a distribution
    :param iam_cert_id: The Id of an IAM certificate
    :param kwargs:
        account_number: AWS account number
    :return:
    """
    try:
        client = kwargs["client"]
        # Get the existing config
        response = client.get_distribution_config(Id=distribution_id)
        config = response["DistributionConfig"]
        viewer_cert = config["ViewerCertificate"]
        if "IAMCertificateId" not in viewer_cert:
            raise InvalidDistribution(distribution_id)
        if iam_cert_id == viewer_cert["IAMCertificateId"]:
            current_app.logger.warning(
                "distribution {} already assigned to IAM certificate {}, not updated".format(
                    distribution_id, iam_cert_id))
            return
        viewer_cert["IAMCertificateId"] = iam_cert_id
        if "Certificate" in viewer_cert:
            del viewer_cert["Certificate"]
        if "CertificateSource" in viewer_cert:
            del viewer_cert["CertificateSource"]

        client.update_distribution(
            Id=distribution_id,
            DistributionConfig=config,
            IfMatch=response["ETag"])
    except Exception as e:  # noqa
        metrics.send("get_distribution_error", "counter", 1)
        capture_exception()
        raise
