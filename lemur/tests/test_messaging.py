import pytest
from freezegun import freeze_time

from datetime import timedelta

from moto import mock_ses


def test_needs_notification(app, certificate, notification):
    from lemur.notifications.messaging import needs_notification
    assert not needs_notification(certificate)

    with pytest.raises(Exception):
        notification.options = [{'name': 'interval', 'value': 10}, {'name': 'unit', 'value': 'min'}]
        certificate.notifications.append(notification)
        needs_notification(certificate)

    certificate.notifications[0].options = [{'name': 'interval', 'value': 10}, {'name': 'unit', 'value': 'days'}]
    assert not needs_notification(certificate)

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert needs_notification(certificate)


@mock_ses
def test_send_expiration_notification(certificate, notification, notification_plugin):
    from lemur.notifications.messaging import send_expiration_notifications
    notification.options = [{'name': 'interval', 'value': 10}, {'name': 'unit', 'value': 'days'}]
    certificate.notifications.append(notification)
    delta = certificate.not_after - timedelta(days=10)

    with freeze_time(delta.datetime):
        sent = send_expiration_notifications()
        assert sent == 1

        certificate.notify = False

        sent = send_expiration_notifications()
        assert sent == 0


@mock_ses
def test_send_rotation_notification(notification_plugin, certificate):
    from lemur.notifications.messaging import send_rotation_notification
    send_rotation_notification(certificate, notification_plugin=notification_plugin)
