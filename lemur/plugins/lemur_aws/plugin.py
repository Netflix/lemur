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
from os.path import join
import sys
from acme.errors import ClientError
from flask import current_app
from sentry_sdk import capture_exception

from lemur.common.utils import check_validation
from lemur.extensions import metrics
from lemur.plugins import lemur_aws as aws, ExpirationNotificationPlugin
from lemur.plugins.bases import DestinationPlugin, ExportDestinationPlugin, SourcePlugin
from lemur.plugins.lemur_aws import iam, s3, elb, ec2, sns, cloudfront, acm


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
            certificate_name=iam.get_name_from_arn(listener["Listener"]["SSLCertificateId"]),
            certificate_path=iam.get_path_from_arn(listener["Listener"]["SSLCertificateId"]),
            registry_type=iam.get_registry_type_from_arn(listener["Listener"]["SSLCertificateId"]),
        )

        if listener["PolicyNames"]:
            policy = elb.describe_load_balancer_policies(
                elb_dict["LoadBalancerName"],
                listener["PolicyNames"],
                account_number=account_number,
                region=region,
            )
            endpoint["policy"] = format_elb_cipher_policy(policy)

        current_app.logger.debug(f"Found new endpoint. Endpoint: {endpoint}")

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
                certificate_path=iam.get_path_from_arn(certificate["CertificateArn"]),
                registry_type=iam.get_registry_type_from_arn(certificate["CertificateArn"]),
            )

        if listener["SslPolicy"]:
            policy = elb.describe_ssl_policies_v2(
                [listener["SslPolicy"]], account_number=account_number, region=region
            )
            endpoint["policy"] = format_elb_cipher_policy_v2(policy)

        endpoints.append(endpoint)

    return endpoints


def get_distribution_endpoint(account_number, cert_id_to_name, distrib_dict):
    """
    Constructs endpoint data from a distribution response, or None if it does
    not represent a distribution Lemur cares about.
    :param account_number:
    :param cert_id_to_name: map of IAM certificate IDs to names
    :param distrib_dict:
    :return: a list of endpoint dictionaries
    """

    cert = distrib_dict["ViewerCertificate"]
    if not cert:
        return None
    # Ignore distributions using the default cert for the cloudfront.net domain
    if cert.get("CloudFrontDefaultCertificate"):
        return None
    # Ignore ACM certificates, since these are auto-rotated
    if cert.get("ACMCertificateArn"):
        return None

    iam_cert_id = cert.get("IAMCertificateId")
    if not iam_cert_id:
        return None

    cert_name = cert_id_to_name.get(iam_cert_id)
    if not cert_name:
        current_app.logger.warning(
            f"get_distribution_endpoints: no IAM certificate with id {iam_cert_id}")
        return None

    policy = dict(
        name='cloudfront-none',
        ciphers=[]
    )
    minimum_version = cert.get("MinimumProtocolVersion")
    if minimum_version:
        policy = dict(
            name=f"cloudfront-%{minimum_version}",
            ciphers=[minimum_version]
        )

    aliases = []
    if "Aliases" in distrib_dict and "Items" in distrib_dict["Aliases"]:
        aliases = distrib_dict["Aliases"]["Items"]

    return dict(
        name=distrib_dict["Id"],
        dnsname=distrib_dict["DomainName"],
        aliases=aliases,
        type="cloudfront",
        port=443,
        certificate_name=cert_name,
        policy=policy,
    )


class AWSSourcePlugin(SourcePlugin):
    title = "AWS"
    slug = "aws-source"
    description = "Discovers all SSL certificates and ELB or Cloudfront endpoints in an AWS account"
    version = aws.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("^[0-9]{12,12}$"),
            "helpMessage": "Must be a valid AWS account number!",
        },
        {
            "name": "regions",
            "type": "str",
            "helpMessage": "Comma separated list of regions to search in, if no region is specified we look in all regions.",
        },
        {
            "name": "path",
            "type": "str",
            "validation": r"^(?:|/|/\S+/)$",
            "default": "/",
            "helpMessage": "Only discover certificates with this path prefix. Must begin and end with slash. "
                           "For CloudFront sources, use '/cloudfront/'.",
        },
        {
            "name": "endpointType",
            "type": "select",
            "available": [
                "elb",          # Discover IAM certs, elb and elbv2 in this account and regions
                "cloudfront",   # Discover IAM certs, CloudFront distributions in this account and regions
                "none",         # Discover IAM certs only in this account and regions
            ],
            "default": "elb",
            "helpMessage": "Type of AWS endpoint to discover. Defaults to elb if not set.",
        },
    ]

    def get_certificates(self, options, **kwargs):
        cert_data = iam.get_all_certificates(
            restrict_path=self.get_option("path", options),
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
        endpoint_type = self.get_option("endpointType", options)
        if endpoint_type == "cloudfront":
            return self.get_distributions(options, **kwargs)
        elif endpoint_type == "none":
            return []
        else:
            return self.get_load_balancers(options, **kwargs)

    def get_load_balancers(self, options, **kwargs):
        endpoints = []
        account_number = self.get_option("accountNumber", options)
        regions = self.get_option("regions", options)

        if not regions:
            regions = ec2.get_regions(account_number=account_number)
        else:
            regions = "".join(regions.split()).split(",")

        for region in regions:
            elbs = elb.get_all_elbs(account_number=account_number, region=region)
            current_app.logger.info({
                "message": "Describing classic load balancers",
                "account_number": account_number,
                "region": region,
                "number_of_load_balancers": len(elbs)
            })

            for e in elbs:
                try:
                    endpoints.extend(get_elb_endpoints(account_number, region, e))
                except Exception:  # noqa
                    capture_exception()
                    continue

            # fetch advanced ELBs
            elbs_v2 = elb.get_all_elbs_v2(account_number=account_number, region=region)
            current_app.logger.info({
                "message": "Describing advanced load balancers",
                "account_number": account_number,
                "region": region,
                "number_of_load_balancers": len(elbs_v2)
            })

            for e in elbs_v2:
                try:
                    endpoints.extend(get_elb_endpoints_v2(account_number, region, e))
                except Exception as e:  # noqa
                    capture_exception()
                    continue
        return endpoints

    def get_distributions(self, options, **kwargs):
        endpoints = []
        account_number = self.get_option("accountNumber", options)
        try:
            iam_cert_dict = iam.get_certificate_id_to_name(account_number=account_number)
            distributions = cloudfront.get_all_distributions(account_number=account_number)
        except Exception as e:  # noqa
            capture_exception()
            return endpoints

        current_app.logger.info({
            "message": "Describing CloudFront distributions",
            "account_number": account_number,
            "number_of_distributions": len(distributions)
        })

        for d in distributions:
            try:
                endpoint = get_distribution_endpoint(account_number, iam_cert_dict, d)
                if endpoint:
                    endpoints.append(endpoint)
            except Exception as e:  # noqa
                capture_exception()
                continue
        return endpoints

    def update_endpoint(self, endpoint, certificate):
        options = endpoint.source.options
        account_number = self.get_option("accountNumber", options)

        if endpoint.type == "cloudfront":
            cert = iam.get_certificate(certificate.name,
                                       account_number=account_number)
            if not cert:
                return None
            cert_id = cert["ServerCertificateMetadata"]["ServerCertificateId"]
            cloudfront.attach_certificate(
                endpoint.name,
                cert_id,
                account_number=account_number
            )
            return

        if endpoint.type not in ["elb", "elbv2"]:
            raise NotImplementedError()

        partition = current_app.config.get("LEMUR_AWS_PARTITION", "aws")
        if endpoint.registry_type == 'iam':
            arn = iam.create_arn_from_cert(account_number, partition, certificate.name, endpoint.certificate_path)
        else:
            raise Exception(f"Lemur doesn't support rotating certificates on {endpoint.registry_type} registry")

        # relies on the fact that region is included in DNS name
        region = get_region_from_dns(endpoint.dnsname)
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
        elif endpoint.type == "elb":
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
                f"get_elb_certificate_failed: Unable to get certificate for {certificate_name}")
            capture_exception()
            metrics.send(
                "get_elb_certificate_failed", "counter", 1,
                metric_tags={"certificate_name": certificate_name, "account_number": account_number}
            )
        return None

    def get_endpoint_certificate_names(self, endpoint):
        options = endpoint.source.options
        account_number = self.get_option("accountNumber", options)
        region = get_region_from_dns(endpoint.dnsname)
        certificate_names = []

        if endpoint.type == "elb":
            elb_details = elb.get_elbs(account_number=account_number,
                                       region=region,
                                       LoadBalancerNames=[endpoint.name],)

            for lb_description in elb_details["LoadBalancerDescriptions"]:
                for listener_description in lb_description["ListenerDescriptions"]:
                    listener = listener_description.get("Listener")
                    if not listener.get("SSLCertificateId"):
                        continue

                    certificate_names.append(iam.get_name_from_arn(listener.get("SSLCertificateId")))
        elif endpoint.type == "elbv2":
            listeners = elb.describe_listeners_v2(
                account_number=account_number,
                region=region,
                LoadBalancerArn=elb.get_load_balancer_arn_from_endpoint(endpoint.name,
                                                                        account_number=account_number,
                                                                        region=region),
            )
            for listener in listeners["Listeners"]:
                if not listener.get("Certificates"):
                    continue

                for certificate in listener["Certificates"]:
                    certificate_names.append(iam.get_name_from_arn(certificate["CertificateArn"]))
        elif endpoint.type == "cloudfront":
            cert_id_to_name = iam.get_certificate_id_to_name(account_number=account_number)
            dist = cloudfront.get_distribution(account_number=account_number, distribution_id=endpoint.name)
            loaded = get_distribution_endpoint(account_number, cert_id_to_name, dist)
            if loaded:
                certificate_names.append(loaded["certificate_name"])
        else:
            raise NotImplementedError()

        return certificate_names


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
            "validation": check_validation("[0-9]{12}"),
            "helpMessage": "Must be a valid AWS account number!",
        },
        {
            "name": "path",
            "type": "str",
            "validation": r"^(?:|/|/\S+/)$",
            "default": "/",
            "helpMessage": "Path prefix for uploaded certificates.",
        },
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        try:
            iam.upload_cert(
                name,
                body,
                private_key,
                self.get_option("path", options),
                cert_chain=cert_chain,
                account_number=self.get_option("accountNumber", options),
            )
        except ClientError:
            capture_exception()

    def deploy(self, elb_name, account, region, certificate):
        pass

    def clean(self, certificate, options, **kwargs):
        account_number = self.get_option("accountNumber", options)
        iam.delete_cert(certificate.name, account_number=account_number)


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
            "validation": check_validation("[0-9a-z.-]{3,63}"),
            "helpMessage": "Must be a valid S3 bucket name!",
        },
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9]{12}"),
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
            "validation": check_validation("^(?:[^/].*|)$"),
            "helpMessage": "Must be a valid S3 object prefix!",
            "default": ""
        },
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def upload(self, name, body, private_key, chain, options, **kwargs):
        files = self.export(body, private_key, chain, options)
        function = f"{__name__}.{sys._getframe().f_code.co_name}"

        for ext, passphrase, data in files:
            filename = join(self.get_option("prefix", options), f"{name}.{ext.lstrip('.')}")
            response = s3.put(
                self.get_option("bucket", options),
                self.get_option("region", options),
                filename,
                data,
                self.get_option("encrypt", options),
                account_number=self.get_option("accountNumber", options),
            )
            res = "Success" if response else "Failure"
            log_data = {
                "function": function,
                "message": "upload s3 file",
                "result": res,
                "bucket_name": self.get_option("bucket", options),
                "filename": filename
            }
            current_app.logger.info(log_data)

    def allow_multiple_per_account(self):
        return True

    def upload_acme_token(self, token_path, token, options, **kwargs):
        """
        This is called from the acme http challenge

        :param self:
        :param token_path:
        :param token:
        :param options:
        :param kwargs:
        :return:
        """
        current_app.logger.debug("S3 destination plugin is started to upload HTTP-01 challenge")

        function = f"{__name__}.{sys._getframe().f_code.co_name}"

        account_number = self.get_option("accountNumber", options)
        bucket_name = self.get_option("bucket", options)
        prefix = self.get_option("prefix", options)
        region = self.get_option("region", options)
        filename = token_path.split("/")[-1]
        if not prefix.endswith("/"):
            prefix + "/"

        response = s3.put(bucket_name=bucket_name,
                          region_name=region,
                          prefix=prefix + filename,
                          data=token,
                          encrypt=False,
                          account_number=account_number)
        res = "Success" if response else "Failure"
        log_data = {
            "function": function,
            "message": "upload acme token challenge",
            "result": res,
            "bucket_name": bucket_name,
            "filename": filename
        }
        current_app.logger.info(log_data)
        metrics.send(f"{function}", "counter", 1, metric_tags={"result": res,
                                                               "bucket_name": bucket_name,
                                                               "filename": filename})
        return response

    def delete_acme_token(self, token_path, options, **kwargs):

        current_app.logger.debug("S3 destination plugin is started to delete HTTP-01 challenge")

        function = f"{__name__}.{sys._getframe().f_code.co_name}"

        account_number = self.get_option("accountNumber", options)
        bucket_name = self.get_option("bucket", options)
        prefix = self.get_option("prefix", options)
        filename = token_path.split("/")[-1]
        response = s3.delete(bucket_name=bucket_name,
                             prefixed_object_name=prefix + filename,
                             account_number=account_number)
        res = "Success" if response else "Failure"
        log_data = {
            "function": function,
            "message": "delete acme token challenge",
            "result": res,
            "bucket_name": bucket_name,
            "filename": filename
        }
        current_app.logger.info(log_data)
        metrics.send(f"{function}", "counter", 1, metric_tags={"result": res,
                                                               "bucket_name": bucket_name,
                                                               "filename": filename})
        return response

    def clean(self, certificate, options, **kwargs):
        files = self.export(certificate.body, certificate.private_key, certificate.chain, options)
        function = f"{__name__}.{sys._getframe().f_code.co_name}"
        prefix = self.get_option("prefix", options)

        for ext, passphrase, data in files:
            filename = join(prefix, f"{certificate.name}.{ext.lstrip('.')}")
            response = s3.delete(bucket_name=self.get_option("bucket", options),
                  prefixed_object_name=filename,
                  account_number=self.get_option("accountNumber", options))
            res = "Success" if response else "Failure"
            log_data = {
                "function": function,
                "message": "delete s3 file",
                "result": res,
                "bucket_name": self.get_option("bucket", options),
                "filename": filename
            }
            current_app.logger.info(log_data)


class SNSNotificationPlugin(ExpirationNotificationPlugin):
    title = "AWS SNS"
    slug = "aws-sns"
    description = "Sends notifications to AWS SNS"
    version = aws.VERSION

    author = "Jasmine Schladen <jschladen@netflix.com>"
    author_url = "https://github.com/Netflix/lemur"

    additional_options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access the SNS topic",
        },
        {
            "name": "region",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9a-z\\-]{1,25}"),
            "helpMessage": "Region in which the SNS topic is located, e.g. \"us-east-1\"",
        },
        {
            "name": "topicName",
            "type": "str",
            "required": True,
            # base topic name is 1-256 characters (alphanumeric plus underscore and hyphen)
            "validation": check_validation("^[a-zA-Z0-9_\\-]{1,256}$"),
            "helpMessage": "The name of the topic to use for expiration notifications",
        }
    ]

    def send(self, notification_type, message, excluded_targets, options, **kwargs):
        """
        While we receive a `targets` parameter here, it is unused, as the SNS topic is pre-configured in the
        plugin configuration, and can't reasonably be changed dynamically.
        """
        partition = current_app.config.get("LEMUR_AWS_PARTITION", "aws")
        topic_arn = f"arn:{partition}:sns:{self.get_option('region', options)}:" \
                    f"{self.get_option('accountNumber', options)}:" \
                    f"{self.get_option('topicName', options)}"

        current_app.logger.info(f"Publishing {notification_type} notification to topic {topic_arn}")
        sns.publish(topic_arn, message, notification_type, options, region_name=self.get_option("region", options))


class AWSACMSourcePlugin(SourcePlugin):
    title = "AWS-ACM"
    slug = "aws-acm-source"
    description = "Discovers all ACM TLS certificates in an AWS account"
    version = aws.VERSION

    author_url = "https://github.com/netflix/lemur"

    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("^[0-9]{12,12}$"),
            "helpMessage": "Must be a valid AWS account number!",
        },
        {
            "name": "regions",
            "type": "str",
            "helpMessage": "Comma separated list of regions to search in, if no region is specified we look in all regions.",
        },
    ]

    def get_certificates(self, options, **kwargs):
        cert_data = acm.get_all_certificates(
            account_number=self.get_option("accountNumber", options)
        )

        return [
            dict(
                body=c["Certificate"],
                chain=c.get("CertificateChain"),
                name=c["name"],
                external_id=c["external_id"],
            )
            for c in cert_data
        ]


class ACMDestinationPlugin(DestinationPlugin):
    title = "AWS-ACM"
    slug = "aws-acm-dest"
    description = "Allow the uploading of certificates to Amazon ACM"
    version = aws.VERSION

    author_url = "https://github.com/Netflix/lemur"

    options = [
        {
            "name": "accountNumber",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9]{12}"),
            "helpMessage": "A valid AWS account number with permission to access ACM",
        },
        {
            "name": "region",
            "type": "str",
            "default": "us-east-1",
            "required": False,
            "helpMessage": "Region bucket exists",
            "available": ["us-east-1", "us-west-2", "eu-west-1"],
        },
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        try:
            acm.upload_cert(
                name,
                body,
                private_key,
                cert_chain=cert_chain,
                account_number=self.get_option("accountNumber", options),
            )
        except ClientError:
            capture_exception()

    def clean(self, certificate, options, **kwargs):
        account_number = self.get_option("accountNumber", options)
        acm.delete_cert(certificate["external_id"], account_number=account_number)
