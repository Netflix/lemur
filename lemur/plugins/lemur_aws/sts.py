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
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from flask import current_app

config = Config(retries=dict(max_attempts=20))


def sts_client(service, service_type="client"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_app.config.get("LEMUR_AWS_REGION"):
                deployment_region = current_app.config.get("LEMUR_AWS_REGION")
                sts = boto3.client(
                    "sts",
                    region_name=deployment_region,
                    endpoint_url=f"https://sts.{deployment_region}.amazonaws.com/",
                    config=config,
                )
            else:
                sts = boto3.client("sts", config=config)
            arn = "arn:{partition}:iam::{account_number}:role/{profile}".format(
                partition=current_app.config.get("LEMUR_AWS_PARTITION", "aws"),
                account_number=kwargs.pop("account_number"),
                profile=current_app.config.get("LEMUR_INSTANCE_PROFILE", "Lemur"),
            )

            def refresh():
                # TODO add user specific information to RoleSessionName
                role = sts.assume_role(RoleArn=arn, RoleSessionName="lemur")
                c = role["Credentials"]
                return {
                    "access_key": c["AccessKeyId"],
                    "secret_key": c["SecretAccessKey"],
                    "token": c["SessionToken"],
                    "expiry_time": c["Expiration"].isoformat(),
                }

            credentials = RefreshableCredentials.create_from_metadata(
                metadata=refresh(),
                refresh_using=refresh,
                method="sts-assume-role",
            )
            botocore_session = get_session()
            botocore_session._credentials = credentials
            session = boto3.Session(botocore_session=botocore_session, region_name=kwargs.pop("region", current_app.config.get("LEMUR_AWS_REGION", "us-east-1")))

            if service_type == "client":
                kwargs["client"] = session.client(service, config=config)
            elif service_type == "resource":
                kwargs["resource"] = session.resource(service, config=config)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
