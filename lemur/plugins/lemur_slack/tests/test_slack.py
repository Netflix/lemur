from datetime import timedelta

import arrow
from moto import mock_ses

from lemur.tests.factories import NotificationFactory, CertificateFactory
from lemur.tests.test_messaging import verify_sender_email


def test_formatting(certificate):
    from lemur.plugins.lemur_slack.plugin import create_expiration_attachments
    from lemur.certificates.schemas import certificate_notification_output_schema

    data = [certificate_notification_output_schema.dump(certificate).data]

    attachment = {
        "title": certificate.name,
        "color": "danger",
        "fields": [
            {"short": True, "value": "joe@example.com", "title": "Owner"},
            {"short": True, "value": u"Tuesday, December 31, 2047", "title": "Expires"},
            {"short": True, "value": 0, "title": "Endpoints Detected"},
        ],
        "title_link": "https://lemur.example.com/#/certificates/{name}".format(
            name=certificate.name
        ),
        "mrkdwn_in": ["text"],
        "text": "",
        "fallback": "",
    }

    assert attachment == create_expiration_attachments(data)[0]


def get_options():
    return [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
        {"name": "webhook", "value": "https://hooks.slack.com/services/api.test"},
    ]


@mock_ses()  # because email notifications are also sent
def test_send_expiration_notification():
    from lemur.notifications.messaging import send_expiration_notifications
    prepare_test()

    assert send_expiration_notifications([], []) == (3, 0)  # owner, Slack, and security


@mock_ses()
def test_send_expiration_notification_slack_disabled():
    from lemur.notifications.messaging import send_expiration_notifications
    prepare_test()

    # though email is not disabled, we don't send the owner/security notifications via email if
    # the main notification's plugin is disabled
    assert send_expiration_notifications([], ['slack-notification']) == (0, 0)


@mock_ses()
def test_send_expiration_notification_email_disabled():
    from lemur.notifications.messaging import send_expiration_notifications
    prepare_test()

    assert send_expiration_notifications([], ['email-notification']) == (1, 0)  # Slack only


@mock_ses()
def test_send_expiration_notification_both_disabled():
    from lemur.notifications.messaging import send_expiration_notifications
    prepare_test()

    assert send_expiration_notifications([], ['slack-notification', 'email-notification']) == (0, 0)


def prepare_test():
    verify_sender_email()  # emails are sent to owner and security; Slack only used for configured notification

    notification = NotificationFactory(plugin_name="slack-notification")
    notification.options = get_options()

    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)  # a bit more than 10 days since we'll check in the future

    certificate = CertificateFactory()
    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)

# Currently disabled as the Slack plugin doesn't support this type of notification
# def test_send_rotation_notification(endpoint, source_plugin):
#     from lemur.notifications.messaging import send_rotation_notification
#     from lemur.deployment.service import rotate_certificate
#
#     notification = NotificationFactory(plugin_name="slack-notification")
#     notification.options = get_options()
#
#     new_certificate = CertificateFactory()
#     rotate_certificate(endpoint, new_certificate)
#     assert endpoint.certificate == new_certificate
#
#     assert send_rotation_notification(new_certificate, notification_plugin=notification.plugin)


# Currently disabled as the Slack plugin doesn't support this type of notification
# def test_send_pending_failure_notification(user, pending_certificate, async_issuer_plugin):
#     from lemur.notifications.messaging import send_pending_failure_notification
#
#     assert send_pending_failure_notification(pending_certificate, notification_plugin=plugins.get("slack-notification"))
