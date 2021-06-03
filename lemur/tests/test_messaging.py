from datetime import timedelta

import arrow
import boto3
import pytest
from freezegun import freeze_time
from moto import mock_ses

from lemur.certificates.service import get_expiring_deployed_certificates
from lemur.tests.factories import AuthorityFactory, CertificateFactory, EndpointFactory


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


def test_get_eligible_certificates_multiple(app, notification):
    from lemur.notifications.messaging import get_eligible_certificates

    options = [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
    ]
    cert_1 = create_cert_that_expires_in_days(10)
    cert_1.notifications.append(notification)
    cert_1.notifications[0].options = options
    cert_2 = create_cert_that_expires_in_days(10)
    # cert 2 has a different owner
    cert_2.notifications.append(notification)
    cert_2.notifications[0].options = options
    cert_3 = create_cert_that_expires_in_days(10)
    cert_3.owner = cert_1.owner
    cert_3.notifications.append(notification)
    cert_3.notifications[0].options = options

    delta = cert_1.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert get_eligible_certificates() == {
            cert_1.owner: {notification.label: [(notification, cert_1), (notification, cert_3)]},
            cert_2.owner: {notification.label: [(notification, cert_2)]}
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
        assert send_expiration_notifications([], []) == (3, 0)


@mock_ses
def test_send_expiration_notification_email_disabled(certificate, notification, notification_plugin):
    from lemur.notifications.messaging import send_expiration_notifications
    verify_sender_email()

    certificate.notifications.append(notification)
    certificate.notifications[0].options = [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
    ]

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        # no notifications sent since the "test-notification" plugin is disabled
        assert send_expiration_notifications([], ['test-notification']) == (0, 0)


@mock_ses
def test_send_expiration_notification_with_no_notifications(
    certificate, notification, notification_plugin
):
    from lemur.notifications.messaging import send_expiration_notifications

    delta = certificate.not_after - timedelta(days=10)
    with freeze_time(delta.datetime):
        assert send_expiration_notifications([], []) == (0, 0)


@mock_ses
def test_send_expiration_summary_notification(certificate, notification, notification_plugin):
    from lemur.notifications.messaging import send_security_expiration_summary
    verify_sender_email()

    # we don't actually test the email contents, but adding an assortment of certs here is useful for step debugging
    # to confirm the produced email body looks like we expect
    create_cert_that_expires_in_days(14)
    create_cert_that_expires_in_days(12)
    create_cert_that_expires_in_days(9)
    create_cert_that_expires_in_days(7)
    create_cert_that_expires_in_days(2)
    create_cert_that_expires_in_days(7)
    create_cert_that_expires_in_days(30)
    create_cert_that_expires_in_days(15)
    create_cert_that_expires_in_days(20)
    create_cert_that_expires_in_days(1)
    create_cert_that_expires_in_days(100)

    assert send_security_expiration_summary([])


@mock_ses
def test_send_evocation_notification(notification_plugin, certificate):
    from lemur.notifications.messaging import send_revocation_notification
    verify_sender_email()

    certificate.endpoints = [EndpointFactory()]
    assert send_revocation_notification(certificate)


@mock_ses
def test_send_rotation_notification(notification_plugin, certificate):
    from lemur.notifications.messaging import send_rotation_notification
    verify_sender_email()

    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)
    assert send_rotation_notification(new_cert)
    new_cert.endpoints = [EndpointFactory()]
    assert send_rotation_notification(new_cert)


@mock_ses
def test_send_reissue_no_endpoints_notification(notification_plugin, endpoint, certificate):
    from lemur.notifications.messaging import send_reissue_no_endpoints_notification
    verify_sender_email()

    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)
    assert send_reissue_no_endpoints_notification(certificate, new_cert)
    certificate.endpoints.append(endpoint)
    assert not send_reissue_no_endpoints_notification(certificate, new_cert)


@mock_ses
def test_send_reissue_no_endpoints_notification_excluded_destination(destination_plugin, notification_plugin,
                                                                     certificate, destination):
    from lemur.notifications.messaging import send_reissue_no_endpoints_notification
    verify_sender_email()

    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)
    destination.label = 'not-excluded-destination'
    certificate.destinations.append(destination)
    assert send_reissue_no_endpoints_notification(certificate, new_cert)
    # specified in tests/conf.py
    destination.label = 'excluded-destination'
    assert not send_reissue_no_endpoints_notification(certificate, new_cert)


@mock_ses
def test_send_reissue_failed_notification(notification_plugin, certificate):
    from lemur.notifications.messaging import send_reissue_failed_notification
    verify_sender_email()

    assert send_reissue_failed_notification(certificate)


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


@mock_ses
def test_send_expiring_deployed_certificate_notifications():
    from lemur.domains.models import Domain
    from lemur.notifications.messaging import send_expiring_deployed_certificate_notifications
    verify_sender_email()

    # three certs with ports, one cert with no ports
    cert_1 = create_cert_that_expires_in_days(10, domains=[Domain(name='domain1.com')], owner='testowner1@example.com')
    cert_1.certificate_associations[0].ports = [1234]
    cert_2 = create_cert_that_expires_in_days(10, domains=[Domain(name='domain1.com')], owner='testowner2@example.com')
    cert_2.certificate_associations[0].ports = [1234, 12345]
    cert_3 = create_cert_that_expires_in_days(10, domains=[Domain(name='domain1.com')], owner='testowner3@example.com')
    cert_3.certificate_associations[0].ports = [1234, 12345, 12456]
    cert_4 = create_cert_that_expires_in_days(10, domains=[Domain(name='domain1.com')], owner='testowner3@example.com')
    cert_4.certificate_associations[0].ports = []

    certificates = get_expiring_deployed_certificates([]).items()
    assert send_expiring_deployed_certificate_notifications(certificates) == (3, 0)  # 3 certs with ports


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


def create_cert_that_expires_in_days(days, serial=None, domains=None, owner=None):
    import random
    from random import randrange
    from string import ascii_lowercase

    now = arrow.utcnow()
    not_after = now + timedelta(days=days, hours=1)  # a bit more than specified since we'll check in the future

    certificate = CertificateFactory()
    certificate.not_after = not_after
    certificate.notify = True
    certificate.owner = ''.join(random.choice(ascii_lowercase) for _ in range(10)) + '@example.com'
    endpoints = []
    for i in range(0, randrange(0, 5)):
        endpoints.append(EndpointFactory())
    certificate.endpoints = endpoints
    if serial:
        certificate.serial = serial
    if owner:
        certificate.owner = owner
    if domains:
        certificate.domains = domains
    return certificate
