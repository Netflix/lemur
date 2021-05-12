import ssl
import threading
from datetime import timedelta
from http.server import SimpleHTTPRequestHandler, HTTPServer
from tempfile import NamedTemporaryFile

import arrow
import boto3
import pytest
from freezegun import freeze_time
from moto import mock_ses
from pytest import fail

from lemur.tests.factories import AuthorityFactory, CertificateFactory, EndpointFactory
from lemur.tests.vectors import INTERMEDIATE_CERT_STR, SAN_CERT_KEY, SAN_CERT_STR, ROOTCA_CERT_STR


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


@mock_ses
def test_send_expiring_deployed_certificate_notifications():
    from lemur.domains.models import Domain
    from lemur.notifications.messaging import send_expiring_deployed_certificate_notifications

    """
    This test spins up three local servers, each serving the same default test cert with a non-matching CN/SANs.
    The logic to check if a cert is still deployed ignores certificate validity; all it needs to know is whether
    the certificate currently deployed at the cert's associated domain has the same serial number as the one in
    Lemur's DB. The expiration check is done using the date in Lemur's DB, and is not parsed from the actual deployed
    certificate - so we can get away with using a totally unrelated cert, as long as the serial number matches.
    In this test, the serial number is always the same, since it's parsed from the hardcoded test cert.
    """

    verify_sender_email()

    # one non-expiring cert, two expiring certs, and one cert that doesn't match a running server
    cert_1 = create_cert_that_expires_in_days(180, domains=[Domain(name='localhost')], owner='testowner1@example.com')
    cert_2 = create_cert_that_expires_in_days(10, domains=[Domain(name='localhost')], owner='testowner2@example.com')
    cert_3 = create_cert_that_expires_in_days(10, domains=[Domain(name='localhost')], owner='testowner3@example.com')
    cert_4 = create_cert_that_expires_in_days(10, domains=[Domain(name='not-localhost')], owner='testowner4@example.com')

    # test certs are all hardcoded with the same body/chain so we don't need to use the created cert here
    cert_file_data = SAN_CERT_STR + INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR + SAN_CERT_KEY
    f = NamedTemporaryFile(suffix='.pem', delete=True)
    try:
        f.write(cert_file_data.encode('utf-8'))
        server_1 = run_server(65521, f.name)
        server_2 = run_server(65522, f.name)
        server_3 = run_server(65523, f.name)
        if not (server_1.is_alive() and server_2.is_alive() and server_3.is_alive()):
            fail('Servers not alive, test cannot proceed')

        assert send_expiring_deployed_certificate_notifications(None) == (2, 0)  # 2 expiring certs with matching domain
        for c in [cert_1, cert_4]:
            for ca in c.certificate_associations:
                assert ca.ports is None
        for c in [cert_2, cert_3]:
            for ca in c.certificate_associations:
                assert ca.ports == [65521, 65522, 65523]
    finally:
        f.close()  # close file (which also deletes it)


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


"""Utility methods to create a mock server that serves a specific certificate"""


def run_server(port, cert_file_name):
    def start_server():
        server = HTTPServer(('localhost', port), SimpleHTTPRequestHandler)
        server.socket = ssl.wrap_socket(server.socket,
                                        server_side=True,
                                        certfile=cert_file_name,
                                        ssl_version=ssl.PROTOCOL_TLS)
        server.serve_forever()
        print(f"Started https server on port {port} using cert file {cert_file_name}")

    daemon = threading.Thread(name=f'server_{cert_file_name}', target=start_server)
    daemon.setDaemon(True)  # Set as a daemon so it will be killed once the main thread is dead.
    daemon.start()
    return daemon
