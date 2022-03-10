"""
.. module: lemur.plugins.lemur_aws.sts
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from functools import wraps

import boto3

from botocore.config import Config
from flask import current_app


config = Config(retries=dict(max_attempts=20))


def sts_client(service, service_type="client"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_app.config.get("LEMUR_AWS_REGION"):
                deployment_region = current_app.config.get("LEMUR_AWS_REGION")
                sts = boto3.client('sts', region_name=deployment_region,
                                   endpoint_url=f"https://sts.{deployment_region}.amazonaws.com/",
                                   config=config)
            else:
                sts = boto3.client("sts", config=config)
            arn = "arn:{partition}:iam::{account_number}:role/{profile}".format(
                partition=current_app.config.get("LEMUR_AWS_PARTITION", "aws"),
                account_number=kwargs.pop("account_number"),
                profile=current_app.config.get("LEMUR_INSTANCE_PROFILE", "Lemur"),
            )

            # TODO add user specific information to RoleSessionName
            role = sts.assume_role(RoleArn=arn, RoleSessionName="lemur")

            if service_type == "client":
                client = boto3.client(
                    service,
                    region_name=kwargs.pop("region", current_app.config.get("LEMUR_AWS_REGION", "us-east-1")),
                    aws_access_key_id=role["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=role["Credentials"]["SecretAccessKey"],
                    aws_session_token=role["Credentials"]["SessionToken"],
                    config=config,
                )
                kwargs["client"] = client
            elif service_type == "resource":
                resource = boto3.resource(
                    service,
                    region_name=kwargs.pop("region", current_app.config.get("LEMUR_AWS_REGION", "us-east-1")),
                    aws_access_key_id=role["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=role["Credentials"]["SecretAccessKey"],
                    aws_session_token=role["Credentials"]["SessionToken"],
                    config=config,
                )
                kwargs["resource"] = resource
            return f(*args, **kwargs)

        return decorated_function

    return decorator
