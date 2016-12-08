import pytest
from freezegun import freeze_time

from datetime import timedelta


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


def test_send_expiration_notification():
    assert False


def test_send_rotation_notification():
    assert False
