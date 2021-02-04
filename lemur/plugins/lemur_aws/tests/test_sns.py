import json
from datetime import timedelta

import arrow
import boto3
from moto import mock_sns, mock_sqs, mock_ses

from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.plugins.lemur_aws.sns import format_message
from lemur.plugins.lemur_aws.sns import publish
from lemur.tests.factories import NotificationFactory, CertificateFactory
from lemur.tests.test_messaging import verify_sender_email


@mock_sns()
def test_format(certificate, endpoint):
    data = [certificate_notification_output_schema.dump(certificate).data]

    for certificate in data:
        expected_message = {
            "notification_type": "expiration",
            "certificate_name": certificate["name"],
            "expires": arrow.get(certificate["validityEnd"]).format("YYYY-MM-DDTHH:mm:ss"),
            "issuer": certificate["issuer"],
            "id": certificate["id"],
            "endpoints_detected": 0,
            "owner": certificate["owner"],
            "details": "https://lemur.example.com/#/certificates/{name}".format(name=certificate["name"])
        }
        assert expected_message == json.loads(format_message(certificate, "expiration"))


@mock_sns()
@mock_sqs()
def create_and_subscribe_to_topic():
    sns_client = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns_client.create_topic(Name='lemursnstest')["TopicArn"]

    sqs_client = boto3.client("sqs", region_name="us-east-1")
    queue = sqs_client.create_queue(QueueName="lemursnstestqueue")
    queue_url = queue["QueueUrl"]
    queue_arn = sqs_client.get_queue_attributes(QueueUrl=queue_url)["Attributes"]["QueueArn"]
    sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    return [topic_arn, sqs_client, queue_url]


@mock_sns()
@mock_sqs()
def test_publish(certificate, endpoint):
    data = [certificate_notification_output_schema.dump(certificate).data]

    topic_arn, sqs_client, queue_url = create_and_subscribe_to_topic()

    message_ids = publish(topic_arn, data, "expiration", region_name="us-east-1")
    assert len(message_ids) == len(data)
    received_messages = sqs_client.receive_message(QueueUrl=queue_url)["Messages"]

    for certificate in data:
        expected_message_id = message_ids[certificate["name"]]
        actual_message = next(
            (m for m in received_messages if json.loads(m["Body"])["MessageId"] == expected_message_id), None)
        actual_json = json.loads(actual_message["Body"])
        assert actual_json["Message"] == format_message(certificate, "expiration")
        assert actual_json["Subject"] == "Lemur: Expiration Notification"


def get_options():
    return [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
        {"name": "region", "value": "us-east-1"},
        {"name": "accountNumber", "value": "123456789012"},
        {"name": "topicName", "value": "lemursnstest"},
    ]


@mock_sns()
@mock_sqs()
@mock_ses()  # because email notifications are also sent
def test_send_expiration_notification():
    from lemur.notifications.messaging import send_expiration_notifications

    verify_sender_email()  # emails are sent to owner and security; SNS only used for configured notification
    topic_arn, sqs_client, queue_url = create_and_subscribe_to_topic()

    notification = NotificationFactory(plugin_name="aws-sns")
    notification.options = get_options()

    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)  # a bit more than 10 days since we'll check in the future

    certificate = CertificateFactory()
    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)

    assert send_expiration_notifications([]) == (3, 0)  # owner, SNS, and security

    received_messages = sqs_client.receive_message(QueueUrl=queue_url)["Messages"]
    assert len(received_messages) == 1
    expected_message = format_message(certificate_notification_output_schema.dump(certificate).data, "expiration")
    actual_message = json.loads(received_messages[0]["Body"])["Message"]
    assert actual_message == expected_message


# Currently disabled as the SNS plugin doesn't support this type of notification
# def test_send_rotation_notification(endpoint, source_plugin):
#     from lemur.notifications.messaging import send_rotation_notification
#     from lemur.deployment.service import rotate_certificate
#
#     notification = NotificationFactory(plugin_name="aws-sns")
#     notification.options = get_options()
#
#     new_certificate = CertificateFactory()
#     rotate_certificate(endpoint, new_certificate)
#     assert endpoint.certificate == new_certificate
#
#     assert send_rotation_notification(new_certificate)


# Currently disabled as the SNS plugin doesn't support this type of notification
# def test_send_pending_failure_notification(user, pending_certificate, async_issuer_plugin):
#     from lemur.notifications.messaging import send_pending_failure_notification
#
#     assert send_pending_failure_notification(pending_certificate)
