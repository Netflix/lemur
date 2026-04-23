from datetime import timedelta

import arrow
import pytest
from moto import mock_ses

from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.tests.factories import NotificationFactory, CertificateFactory
from lemur.tests.test_messaging import verify_sender_email


def test_formatting(certificate):
    from lemur.plugins.lemur_telegram.plugin import create_expiration_attachments
    data = [certificate_notification_output_schema.dump(certificate).data]
    attachments = create_expiration_attachments(data)
    body = attachments[0]
    assert certificate.name in body
    assert "Owner:" in body
    assert "Expires:" in body
    assert "Endpoints:" in body
    assert "https://" in body
    assert certificate.name in body.split("(")[1]


def get_options():
    return [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
        {"name": "chat", "value": "12345"},
        {"name": "token", "value": "999:TESTTOKEN"},
    ]


def prepare_test():
    verify_sender_email()
    notification = NotificationFactory(plugin_name="tg-notification")
    notification.options = get_options()
    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)
    certificate = CertificateFactory()
    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)


@mock_ses()
def test_send_expiration_notification(mocker):
    from lemur.notifications.messaging import send_expiration_notifications
    # Telegram API request mock
    mock_post = mocker.patch(
        "lemur.plugins.lemur_telegram.plugin.requests.post"
    )
    mock_post.return_value.status_code = 200

    prepare_test()

    sent, failed = send_expiration_notifications([], [])

    # Why 3:
    # - owner email
    # - security email
    # - telegram notification
    assert (sent, failed) == (3, 0)

    # Ensure Telegram was hit
    assert mock_post.called
    data = mock_post.call_args[1]["data"]
    assert "Lemur Expiration Notification" in data["text"]
    assert data["chat_id"] == "12345"


@mock_ses()
def test_send_expiration_notification_telegram_disabled(mocker):
    from lemur.notifications.messaging import send_expiration_notifications

    mocker.patch(
        "lemur.plugins.lemur_telegram.plugin.requests.post"
    )

    prepare_test()

    # Disabling telegram means: owner+security emails SHOULD NOT be skipped,
    # but messaging rules say: if the *main* plugin (tg-notification) disabled → skip all
    assert send_expiration_notifications([], ["tg-notification"]) == (0, 0)


@mock_ses()
def test_send_expiration_notification_email_disabled(mocker):
    from lemur.notifications.messaging import send_expiration_notifications

    mocker.patch(
        "lemur.plugins.lemur_telegram.plugin.requests.post"
    )

    prepare_test()

    # Email disabled → Telegram still fires
    # sent, failed =
    assert send_expiration_notifications([], ["email-notification"]) == (0, 1)


@mock_ses()
def test_send_expiration_notification_both_disabled(mocker):
    from lemur.notifications.messaging import send_expiration_notifications

    mocker.patch(
        "lemur.plugins.lemur_telegram.plugin.requests.post"
    )

    prepare_test()

    assert send_expiration_notifications([], ["tg-notification", "email-notification"]) == (0, 0)


def test_send_failure_on_bad_status(mocker, certificate):
    from lemur.plugins.lemur_telegram.plugin import TelegramNotificationPlugin

    plugin = TelegramNotificationPlugin()

    mock_post = mocker.patch(
        "lemur.plugins.lemur_telegram.plugin.requests.post"
    )
    mock_post.return_value.status_code = 403

    options = {"chat": "12345", "token": "999:BAD"}

    cert_data = [certificate_notification_output_schema.dump(certificate).data]

    with pytest.raises(Exception):
        plugin.send("expiration", cert_data, None, options)


def test_unsupported_notification_type_raises(mocker):
    from lemur.plugins.lemur_telegram.plugin import TelegramNotificationPlugin

    plugin = TelegramNotificationPlugin()

    mocker.patch("lemur.plugins.lemur_telegram.plugin.requests.post")

    with pytest.raises(Exception) as exc:
        plugin.send("unknown", {}, None, {"chat": "1", "token": "999:X"})

    assert "Unable to create message attachments" in str(exc.value)
