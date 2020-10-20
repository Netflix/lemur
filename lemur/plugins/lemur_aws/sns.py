"""
.. module: lemur.plugins.lemur_aws.sts
    :platform: Unix
    :copyright: (c) 2020 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json

import arrow
import boto3
from flask import current_app


def publish(topic_arn, certificates, notification_type, **kwargs):
    sns_client = boto3.client("sns", **kwargs)
    message_ids = {}
    for certificate in certificates:
        message_ids[certificate["name"]] = publish_single(sns_client, topic_arn, certificate, notification_type)

    return message_ids


def publish_single(sns_client, topic_arn, certificate, notification_type):
    response = sns_client.publish(
        TopicArn=topic_arn,
        Message=format_message(certificate, notification_type),
    )

    response_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if response_code != 200:
        raise Exception(f"Failed to publish notification to SNS, response code was {response_code}")

    current_app.logger.debug(f"AWS SNS message published to topic [{topic_arn}]: [{response}]")

    return response["MessageId"]


def create_certificate_url(name):
    return "https://{hostname}/#/certificates/{name}".format(
        hostname=current_app.config.get("LEMUR_HOSTNAME"), name=name
    )


def format_message(certificate, notification_type):
    json_message = {
        "notification_type": notification_type,
        "certificate_name": certificate["name"],
        "expires": arrow.get(certificate["validityEnd"]).format("dddd, MMMM D, YYYY"),
        "endpoints_detected": len(certificate["endpoints"]),
        "details": create_certificate_url(certificate["name"])
    }
    return json.dumps(json_message)
