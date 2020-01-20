"""
.. module: lemur.plugins.lemur_aws.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Terraform example to setup the destination bucket:
    resource "aws_s3_bucket" "certs_log_bucket" {
         bucket = "certs-log-access-bucket"
        acl    = "log-delivery-write"
    }

    resource "aws_s3_bucket" "certs_lemur" {
        bucket = "certs-lemur"
        acl    = "private"

      logging {
        target_bucket = "${aws_s3_bucket.certs_log_bucket.id}"
        target_prefix = "log/lemur"
      }
    }

    The IAM role Lemur is running as should have the following actions on the destination bucket:

    "S3:PutObject",
    "S3:PutObjectAcl"

    The reader should have the following actions:
    "s3:GetObject"

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
.. moduleauthor:: Harm Weites <harm@weites.com>
"""
from acme.errors import ClientError
from flask import current_app
from lemur.extensions import sentry, metrics

from lemur.plugins import lemur_aws as aws
from lemur.plugins.bases import DestinationPlugin, ExportDestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam, s3, elb, ec2


def get_region_from_dns(dns):
    #  XXX.REGION.elb.amazonaws.com
    if dns.endswith(".elb.amazonaws.com"):
        return dns.split(".")[-4]
    else:
        #  NLBs have a different pattern on the dns XXXX.elb.REGION.amazonaws.com
        return dns.split(".")[-3]


def format_elb_cipher_policy_v2(policy):
    """
    Attempts to format cipher policy information for elbv2 into a common format.
    :param policy:
    :return:
    """
    ciphers = []
    name = None

    for descr in policy["SslPolicies"]:
        name = descr["Name"]
        for cipher in descr["Ciphers"]:
            ciphers.append(cipher["Name"])

    return dict(name=name, ciphers=ciphers)


def format_elb_cipher_policy(policy):
    """
    Attempts to format cipher policy information into a common format.
    :param policy:
    :return:
    """
    ciphers = []
    name = None
    for descr in policy["PolicyDescriptions"]:
        for attr in descr["PolicyAttributeDescriptions"]:
            if attr["AttributeName"] == "Reference-Security-Policy":
                name = attr["AttributeValue"]
                continue

            if attr["AttributeValue"] == "true":
                ciphers.append(attr["AttributeName"])

    return dict(name=name, ciphers=ciphers)


def get_elb_endpoints(account_number, region, elb_dict):
    """
    Retrieves endpoint information from elb response data.
    :param account_number:
    :param region:
    :param elb_dict:
    :return:
    """
    endpoints = []
    for listener in elb_dict["ListenerDescriptions"]:
        if not listener["Listener"].get("SSLCertificateId"):
            continue

        if listener["Listener"]["SSLCertificateId"] == "Invalid-Certificate":
            continue

        endpoint = dict(
            name=elb_dict["LoadBalancerName"],
            dnsname=elb_dict["DNSName"],
            type="elb",
            port=listener["Listener"]["LoadBalancerPort"],
            certificate_name=iam.get_name_from_arn(
                listener["Listener"]["SSLCertificateId"]
            ),
        )

        if listener["PolicyNames"]:
            policy = elb.describe_load_balancer_policies(
                elb_dict["LoadBalancerName"],
                listener["PolicyNames"],
                account_number=account_number,
                region=region,
            )
            endpoint["policy"] = format_elb_cipher_policy(policy)

        current_app.logger.debug("Found new endpoint. Endpoint: {}".format(endpoint))

        endpoints.append(endpoint)

    return endpoints


def get_elb_endpoints_v2(account_number, region, elb_dict):
    """
    Retrieves endpoint information from elbv2 response data.
    :param account_number:
    :param region:
    :param elb_dict:
    :return:
    """
    endpoints = []
    listeners = elb.describe_listeners_v2(
        account_number=account_number,
        region=region,
        LoadBalancerArn=elb_dict["LoadBalancerArn"],
    )
    for listener in listeners["Listeners"]:
        if not listener.get("Certificates"):
            continue

        for certificate in listener["Certificates"]:
            endpoint = dict(
                name=elb_dict["LoadBalancerName"],
                dnsname=elb_dict["DNSName"],
                type="elbv2",
                port=listener["Port"],
                certificate_name=iam.get_name_from_arn(certificate["CertificateArn"]),
            )

        if listener["SslPolicy"]:
            policy = elb.describe_ssl_policies_v2(
                [listener["SslPolicy"]], account_number=account_number, region=region
            )
            endpoint["policy"] = format_elb_cipher_policy_v2(policy)

        endpoints.append(endpoint)

    return endpoints


class AWSSourcePlugin(SourcePlugin):
    title = "AWS"
    slug = "aws-source"
    description = "Discovers all SSL certificates and ELB endpoints in an AWS account"
    version = aws.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": "/^[0-9]{12,12}$/",
            "helpMessage": "Must be a valid AWS account number!",
        },
        {
            "name": "regions",
            "type": "str",
            "helpMessage": "Comma separated list of regions to search in, if no region is specified we look in all regions.",
        },
    ]

    def get_certificates(self, options, **kwargs):
        cert_data = iam.get_all_certificates(
            account_number=self.get_option("accountNumber", options)
        )
        return [
            dict(
                body=c["CertificateBody"],
                chain=c.get("CertificateChain"),
                name=c["ServerCertificateMetadata"]["ServerCertificateName"],
            )
            for c in cert_data
        ]

    def get_endpoints(self, options, **kwargs):
        endpoints = []
        account_number = self.get_option("accountNumber", options)
        regions = self.get_option("regions", options)

        if not regions:
            regions = ec2.get_regions(account_number=account_number)
        else:
            regions = "".join(regions.split()).split(",")

        for region in regions:
            elbs = elb.get_all_elbs(account_number=account_number, region=region)
            current_app.logger.info(
                "Describing classic load balancers in {0}-{1}".format(
                    account_number, region
                )
            )

            for e in elbs:
                endpoints.extend(get_elb_endpoints(account_number, region, e))

            # fetch advanced ELBs
            elbs_v2 = elb.get_all_elbs_v2(account_number=account_number, region=region)
            current_app.logger.info(
                "Describing advanced load balancers in {0}-{1}".format(
                    account_number, region
                )
            )

            for e in elbs_v2:
                endpoints.extend(get_elb_endpoints_v2(account_number, region, e))

        return endpoints

    def update_endpoint(self, endpoint, certificate):
        options = endpoint.source.options
        account_number = self.get_option("accountNumber", options)

        # relies on the fact that region is included in DNS name
        region = get_region_from_dns(endpoint.dnsname)
        arn = iam.create_arn_from_cert(account_number, region, certificate.name)

        if endpoint.type == "elbv2":
            listener_arn = elb.get_listener_arn_from_endpoint(
                endpoint.name,
                endpoint.port,
                account_number=account_number,
                region=region,
            )
            elb.attach_certificate_v2(
                listener_arn,
                endpoint.port,
                [{"CertificateArn": arn}],
                account_number=account_number,
                region=region,
            )
        else:
            elb.attach_certificate(
                endpoint.name,
                endpoint.port,
                arn,
                account_number=account_number,
                region=region,
            )

    def clean(self, certificate, options, **kwargs):
        account_number = self.get_option("accountNumber", options)
        iam.delete_cert(certificate.name, account_number=account_number)

    def get_certificate_by_name(self, certificate_name, options):
        account_number = self.get_option("accountNumber", options)
        # certificate name may contain path, in which case we remove it
        if "/" in certificate_name:
            certificate_name = certificate_name.split('/')[-1]
        try:
            cert = iam.get_certificate(certificate_name, account_number=account_number)
            if cert:
                return dict(
                    body=cert["CertificateBody"],
                    chain=cert.get("CertificateChain"),
                    name=cert["ServerCertificateMetadata"]["ServerCertificateName"],
                )
        except ClientError:
            current_app.logger.warning(
                "get_elb_certificate_failed: Unable to get certificate for {0}".format(certificate_name))
            sentry.captureException()
            metrics.send(
                "get_elb_certificate_failed", "counter", 1,
                metric_tags={"certificate_name": certificate_name, "account_number": account_number}
            )
        return None


class AWSDestinationPlugin(DestinationPlugin):
    title = "AWS"
    slug = "aws-destination"
    description = "Allow the uploading of certificates to AWS IAM"
    version = aws.VERSION
    sync_as_source = True
    sync_as_source_name = AWSSourcePlugin.slug

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": "[0-9]{12}",
            "helpMessage": "Must be a valid AWS account number!",
        },
        {
            "name": "path",
            "type": "str",
            "default": "/",
            "helpMessage": "Path to upload certificate.",
        },
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        iam.upload_cert(
            name,
            body,
            private_key,
            self.get_option("path", options),
            cert_chain=cert_chain,
            account_number=self.get_option("accountNumber", options),
        )

    def deploy(self, elb_name, account, region, certificate):
        pass


class S3DestinationPlugin(ExportDestinationPlugin):
    title = "AWS-S3"
    slug = "aws-s3"
    description = "Allow the uploading of certificates to Amazon S3"

    author = "Mikhail Khodorovskiy, Harm Weites <harm@weites.com>"
    author_url = "https://github.com/Netflix/lemur"

    additional_options = [
        {
            "name": "bucket",
            "type": "str",
            "required": True,
            "validation": "[0-9a-z.-]{3,63}",
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": "[0-9]{12}",
            "helpMessage": "A valid AWS account number with permission to access S3",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
        {
            "name": "encrypt",
            "type": "bool",
            "required": False,
            "helpMessage": "Enable server side encryption",
            "default": True,
        },
        {
            "name": "prefix",
            "type": "str",
            "required": False,
            "helpMessage": "Must be a valid S3 object prefix!",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(S3DestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, chain, options, **kwargs):
        files = self.export(body, private_key, chain, options)

        for ext, passphrase, data in files:
            s3.put(
                self.get_option("bucket", options),
                self.get_option("region", options),
                "{prefix}/{name}.{extension}".format(
                    prefix=self.get_option("prefix", options), name=name, extension=ext
                ),
                data,
                self.get_option("encrypt", options),
                account_number=self.get_option("accountNumber", options),
            )
