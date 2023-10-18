import os
from collections import defaultdict
from datetime import timedelta

import arrow
from moto import mock_ses

from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.plugins.lemur_email.plugin import render_html
from lemur.tests.factories import CertificateFactory, EndpointFactory
from lemur.tests.test_messaging import verify_sender_email, create_cert_that_expires_in_days

dir_path = os.path.dirname(os.path.realpath(__file__))


def get_options():
    return [
        {"name": "interval", "value": 10},
        {"name": "unit", "value": "days"},
        {"name": "recipients", "value": "person1@example.com,person2@example.com"},
    ]


def test_render_expiration(certificate, endpoint):
    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)

    assert render_html("expiration", get_options(), [certificate_notification_output_schema.dump(certificate)])


def test_render_revocation(certificate, endpoint):
    certificate.endpoints.append(endpoint)

    assert render_html("revocation", get_options(), certificate_notification_output_schema.dump(certificate))


def test_render_rotation(certificate, endpoint):
    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)
    new_cert.endpoints.append(endpoint)

    assert render_html("rotation", get_options(), certificate_notification_output_schema.dump(new_cert))


def test_render_reissue_failed(certificate):
    assert render_html("reissue_failed", get_options(), certificate_notification_output_schema.dump(certificate))


def test_render_reissued_with_no_endpoints(certificate):
    new_cert = CertificateFactory()
    new_cert.replaces.append(certificate)

    assert render_html("reissued_with_no_endpoints", get_options(),
                       certificate_notification_output_schema.dump(new_cert))


def test_render_rotation_failure(pending_certificate):
    assert render_html("failed", get_options(), certificate_notification_output_schema.dump(pending_certificate))


def test_render_expiration_summary(certificate, notification, notification_plugin):
    from lemur.notifications.messaging import get_eligible_security_summary_certs
    verify_sender_email()

    expected_certs = defaultdict(list)
    # weird order to ensure they're not all sequential in the DB
    expected_certs["14"].append(create_cert_that_expires_in_days(14))
    expected_certs["12"].append(create_cert_that_expires_in_days(12))
    expected_certs["1"].append(create_cert_that_expires_in_days(1))
    expected_certs["3"].append(create_cert_that_expires_in_days(3))
    expected_certs["2"].append(create_cert_that_expires_in_days(2))
    expected_certs["9"].append(create_cert_that_expires_in_days(9))
    expected_certs["7"].append(create_cert_that_expires_in_days(7))
    expected_certs["12"].append(create_cert_that_expires_in_days(12))
    expected_certs["7"].append(create_cert_that_expires_in_days(7))
    expected_certs["2"].append(create_cert_that_expires_in_days(2))
    expected_certs["2"].append(create_cert_that_expires_in_days(2))
    expected_certs["3"].append(create_cert_that_expires_in_days(3))
    expected_certs["2"].append(create_cert_that_expires_in_days(2))
    create_cert_that_expires_in_days(15)  # over the limit, won't be included
    expected_certs["1"].append(create_cert_that_expires_in_days(1))

    message_data = get_eligible_security_summary_certs(None)
    assert len(message_data) == len(expected_certs)  # verify the expected number of intervals
    for interval in expected_certs:
        message_data_for_interval = [x for x in message_data if x['interval'] == int(interval)]
        assert len(message_data_for_interval) > 0  # verify the interval is present in the message data
        message_data_for_interval = message_data_for_interval[0]
        assert message_data_for_interval['certificates']  # verify the interval in the message data has a certs field
        for cert in expected_certs[interval]:
            message_data_for_cert = [x for x in message_data_for_interval['certificates'] if x['name'] == cert.name]
            assert message_data_for_cert  # verify the expected cert is present for the expected interval


def test_render_expiring_deployed_certificate(certificate):
    verify_sender_email()

    cert_data = certificate_notification_output_schema.dump(certificate)
    cert_data['domains_and_ports'] = [{'domain': 'subdomain.example.com', 'ports': [443]},
                                      {'domain': 'example.com', 'ports': [443, 444]}]

    assert render_html("expiring_deployed_certificate", get_options(), [cert_data])


@mock_ses
def test_send_expiration_notification_no_security_team():
    from lemur.notifications.messaging import send_expiration_notifications
    from lemur.tests.factories import CertificateFactory
    from lemur.tests.factories import NotificationFactory

    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)  # a bit more than 10 days since we'll check in the future
    certificate = CertificateFactory(name="TEST1")
    notification = NotificationFactory(plugin_name="email-notification")

    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)
    certificate.notifications[0].options = get_options()

    verify_sender_email()
    assert send_expiration_notifications([], [], True) == (3, 0)  # owner (1) and recipients (2)


@mock_ses
def test_send_expiration_notification():
    from lemur.notifications.messaging import send_expiration_notifications
    from lemur.tests.factories import CertificateFactory
    from lemur.tests.factories import NotificationFactory

    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)  # a bit more than 10 days since we'll check in the future
    certificate = CertificateFactory()
    notification = NotificationFactory(plugin_name="email-notification")

    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)
    certificate.notifications[0].options = get_options()

    verify_sender_email()
    # exclude "TEST1" certs so we don't pick up certs from the last test tests
    assert send_expiration_notifications(["TEST1"], []) == (4, 0)  # owner (1), recipients (2), and security (1)


@mock_ses
def test_send_expiration_notification_disabled():
    from lemur.notifications.messaging import send_expiration_notifications
    from lemur.tests.factories import CertificateFactory
    from lemur.tests.factories import NotificationFactory

    now = arrow.utcnow()
    in_ten_days = now + timedelta(days=10, hours=1)  # a bit more than 10 days since we'll check in the future
    certificate = CertificateFactory()
    notification = NotificationFactory(plugin_name="email-notification")

    certificate.not_after = in_ten_days
    certificate.notifications.append(notification)
    certificate.notifications[0].options = get_options()

    verify_sender_email()
    assert send_expiration_notifications([], ['email-notification']) == (0, 0)


@mock_ses
def test_send_revocation_notification(certificate, endpoint):
    from lemur.notifications.messaging import send_revocation_notification

    verify_sender_email()
    certificate.endpoints = [endpoint]
    assert send_revocation_notification(certificate)


@mock_ses
def test_send_rotation_notification(certificate, endpoint, source_plugin):
    from lemur.notifications.messaging import send_rotation_notification
    from lemur.deployment.service import rotate_certificate

    new_certificate = CertificateFactory()
    rotate_certificate(endpoint, new_certificate)
    new_certificate.replaces.append(certificate)
    assert endpoint.certificate == new_certificate

    verify_sender_email()
    assert send_rotation_notification(new_certificate)
    new_certificate.endpoints = [EndpointFactory()]
    assert send_rotation_notification(new_certificate)


@mock_ses
def test_send_reissue_failed_notification(certificate):
    from lemur.notifications.messaging import send_reissue_failed_notification

    verify_sender_email()
    certificate.endpoints = [EndpointFactory()]
    assert send_reissue_failed_notification(certificate)


@mock_ses
def test_send_reissue_no_endpoints_notification(certificate):
    from lemur.notifications.messaging import send_reissue_no_endpoints_notification

    verify_sender_email()
    new_certificate = CertificateFactory()
    new_certificate.replaces.append(certificate)
    verify_sender_email()
    assert send_reissue_no_endpoints_notification(certificate, new_certificate)


@mock_ses
def test_send_pending_failure_notification(user, pending_certificate, async_issuer_plugin):
    from lemur.notifications.messaging import send_pending_failure_notification

    verify_sender_email()
    assert send_pending_failure_notification(pending_certificate)
    assert send_pending_failure_notification(pending_certificate, True, True)
    assert send_pending_failure_notification(pending_certificate, True, False)
    assert send_pending_failure_notification(pending_certificate, False, True)
    assert send_pending_failure_notification(pending_certificate, False, False)


def test_get_recipients(certificate, endpoint):
    from lemur.plugins.lemur_email.plugin import EmailNotificationPlugin

    options = [{"name": "recipients", "value": "security@example.com,joe@example.com"}]
    two_emails = sorted(["security@example.com", "joe@example.com"])
    assert sorted(EmailNotificationPlugin.get_recipients(options, [])) == two_emails
    assert sorted(EmailNotificationPlugin.get_recipients(options, ["security@example.com"])) == two_emails
    three_emails = sorted(["security@example.com", "bob@example.com", "joe@example.com"])
    assert sorted(EmailNotificationPlugin.get_recipients(options, ["bob@example.com"])) == three_emails
    assert sorted(EmailNotificationPlugin.get_recipients(options, ["security@example.com", "bob@example.com",
                                                                   "joe@example.com"])) == three_emails


def test_title_parser(certificate, endpoint):
    from lemur.plugins.lemur_email.plugin import TitleParser

    html_template_with_title = """
    <html>
        <head><title>The Title!</title></head>
        <body><p>Here's your email!</p></body>
    </html>"""
    with_title = TitleParser()
    with_title.feed(html_template_with_title)
    assert (with_title.title)

    html_template_without_title = """
    <html>
        <body><p>Here's your email!</p></body>
    </html>"""
    without_title = TitleParser()
    without_title.feed(html_template_without_title)
    assert (not without_title.title)
