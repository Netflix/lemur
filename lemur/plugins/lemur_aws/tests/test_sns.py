from moto import mock_sts, mock_sns, mock_sqs
import boto3
import json

import arrow
from lemur.plugins.lemur_aws.sns import format_message
from lemur.plugins.lemur_aws.sns import publish
from lemur.certificates.schemas import certificate_notification_output_schema

@mock_sns()
def test_format(certificate, endpoint):

    data = [certificate_notification_output_schema.dump(certificate).data]

    for certificate in data:
        expected_message = {
            "notification_type": "expiration",
            "certificate_name": certificate["name"],
            "expires": arrow.get(certificate["validityEnd"]).format("dddd, MMMM D, YYYY"),
            "endpoints_detected": 0,
            "details": "https://lemur.example.com/#/certificates/{name}".format(name=certificate["name"])
        }
        assert expected_message == json.loads(format_message(certificate, "expiration"))


@mock_sns()
@mock_sqs()
def test_publish(certificate, endpoint):

    data = [certificate_notification_output_schema.dump(certificate).data]

    sns_client = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns_client.create_topic(Name='lemursnstest')["TopicArn"]

    sqs_client = boto3.client("sqs", region_name="us-east-1")
    queue = sqs_client.create_queue(QueueName="lemursnstestqueue")
    queue_url = queue["QueueUrl"]
    queue_arn = sqs_client.get_queue_attributes(QueueUrl=queue_url)["Attributes"]["QueueArn"]
    sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    message_ids = publish(topic_arn, data, "expiration", region_name="us-east-1")
    assert len(message_ids) == len(data)
    received_messages = sqs_client.receive_message(QueueUrl=queue_url)["Messages"]

    print("ALPACA: Received messages = {}".format(received_messages))

    for certificate in data:
        expected_message_id = message_ids[certificate["name"]]
        actual_message = next((m for m in received_messages if json.loads(m["Body"])["MessageId"] == expected_message_id), None)
        assert json.loads(actual_message["Body"])["Message"] == format_message(certificate, "expiration")
