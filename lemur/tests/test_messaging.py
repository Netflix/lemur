from datetime import timedelta

import arrow
import boto3
import pytest
from freezegun import freeze_time
from moto import mock_ses
from lemur.tests.factories import AuthorityFactory, CertificateFactory


@mock_ses
def verify_sender_email():
    ses_client = boto3.client("ses", region_name="us-east-1")
    ses_client.verify_email_identity(EmailAddress="lemur@example.com")


def test_needs_notification(app, certificate, notification):
    from lemur.notifications.messaging import needs_notification

    assert not needs_notification(certificate)

    with pytest.raises(Exception):
        notification.options = [
            {"name": "interval", "value": 10},
            {"name": "unit", "value": "min"},
        ]
        certificate.notifications.append(notification)
        needs_notification(certificate)

    certificate.notifications[0].options = [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
    ]
    assert not needs_notification(certificate)

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert needs_notification(certificate)


def test_get_certificates(app, certificate, notification):
    from lemur.notifications.messaging import get_certificates

    certificate.not_after = arrow.utcnow() + timedelta(days=30)
    delta = certificate.not_after - timedelta(days=2)

    notification.options = [
        {"name": "interval", "value": 2},
        {"name": "unit", "value": "days"},
    ]

    with freeze_time(delta.datetime):
        # no notification
        certs = len(get_certificates())

        # with notification
        certificate.notifications.append(notification)
        assert len(get_certificates()) > certs

        certificate.notify = False
        assert len(get_certificates()) == certs

    # expired
    delta = certificate.not_after + timedelta(days=2)
    with freeze_time(delta.datetime):
        certificate.notifications.append(notification)
        assert len(get_certificates()) == 0


def test_get_eligible_certificates(app, certificate, notification):
    from lemur.notifications.messaging import get_eligible_certificates

    certificate.notifications.append(notification)
    certificate.notifications[0].options = [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
    ]

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert get_eligible_certificates() == {
            certificate.owner: {notification.label: [(notification, certificate)]}
        }


@mock_ses
def test_send_expiration_notification(certificate, notification, notification_plugin):
    from lemur.notifications.messaging import send_expiration_notifications
    verify_sender_email()

    certificate.notifications.append(notification)
    certificate.notifications[0].options = [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
    ]

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        # this will only send owner and security emails (no additional recipients),
        # but it executes 3 successful send attempts
        assert send_expiration_notifications([]) == (3, 0)


@mock_ses
def test_send_expiration_notification_with_no_notifications(
    certificate, notification, notification_plugin
):
    from lemur.notifications.messaging import send_expiration_notifications

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert send_expiration_notifications([]) == (0, 0)


@mock_ses
def test_send_rotation_notification(notification_plugin, certificate):
    from lemur.notifications.messaging import send_rotation_notification
    verify_sender_email()

    assert send_rotation_notification(certificate)


@mock_ses
def test_send_pending_failure_notification(notification_plugin, async_issuer_plugin, pending_certificate):
    from lemur.notifications.messaging import send_pending_failure_notification
    verify_sender_email()

    assert send_pending_failure_notification(pending_certificate)


def test_get_authority_certificates():
    from lemur.notifications.messaging import get_expiring_authority_certificates

    certificate_1 = create_ca_cert_that_expires_in_days(180)
    certificate_2 = create_ca_cert_that_expires_in_days(365)
    create_ca_cert_that_expires_in_days(364)
    create_ca_cert_that_expires_in_days(366)
    create_ca_cert_that_expires_in_days(179)
    create_ca_cert_that_expires_in_days(181)
    create_ca_cert_that_expires_in_days(1)

    assert set(get_expiring_authority_certificates()) == {certificate_1, certificate_2}


@mock_ses
def test_send_authority_expiration_notifications():
    from lemur.notifications.messaging import send_authority_expiration_notifications
    verify_sender_email()

    create_ca_cert_that_expires_in_days(180)
    create_ca_cert_that_expires_in_days(180)  # two on the same day results in a single email
    create_ca_cert_that_expires_in_days(365)
    create_ca_cert_that_expires_in_days(364)
    create_ca_cert_that_expires_in_days(366)
    create_ca_cert_that_expires_in_days(179)
    create_ca_cert_that_expires_in_days(181)
    create_ca_cert_that_expires_in_days(1)

    assert send_authority_expiration_notifications() == (2, 0)


def create_ca_cert_that_expires_in_days(days):
    now = arrow.utcnow()
    not_after = now + timedelta(days=days, hours=1)  # a bit more than specified since we'll check in the future

    authority = AuthorityFactory()
    certificate = CertificateFactory()
    certificate.not_after = not_after
    certificate.notify = True
    certificate.root_authority_id = authority.id
    certificate.authority_id = None
    return certificate
