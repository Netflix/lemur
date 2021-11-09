"""
.. module: lemur.notifications.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from flask_script import Manager
from sentry_sdk import capture_exception

from lemur.certificates.service import get_expiring_deployed_certificates
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.extensions import metrics
from lemur.notifications.messaging import send_expiration_notifications, \
    send_expiring_deployed_certificate_notifications
from lemur.notifications.messaging import send_authority_expiration_notifications
from lemur.notifications.messaging import send_security_expiration_summary

manager = Manager(usage="Handles notification related tasks.")


@manager.option(
    "-e",
    "--exclude",
    dest="exclude",
    action="append",
    default=[],
    help="Common name matching of certificates that should be excluded from notification",
)
@manager.option(
    "-d",
    "--disabled-notification-plugins",
    dest="disabled_notification_plugins",
    action="append",
    default=[],
    help="List of notification plugins for which notifications should NOT be sent",
)
def expirations(exclude, disabled_notification_plugins):
    """
    Runs Lemur's notification engine, that looks for expiring certificates and sends
    notifications out to those that have subscribed to them.

    Every certificate receives notifications by default. When expiration notifications are handled outside of Lemur
    we exclude their names (or matching) from expiration notifications.

    It performs simple subset matching and is case insensitive.

    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("Starting to notify subscribers about expiring certificates!")
        disable_security_team_emails = current_app.config.get("LEMUR_DISABLE_SECURITY_TEAM_EXPIRATION_EMAILS", False)
        success, failed = send_expiration_notifications(exclude, disabled_notification_plugins, disable_security_team_emails)
        print(
            f"Finished notifying subscribers about expiring certificates! Sent: {success} Failed: {failed}"
        )
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        capture_exception()

    metrics.send(
        "expiration_notification_job", "counter", 1, metric_tags={"status": status}
    )


def authority_expirations():
    """
    Runs Lemur's notification engine, that looks for expiring certificate authority certificates and sends
    notifications out to the security team and owner.

    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("Starting to notify subscribers about expiring certificate authority certificates!")
        success, failed = send_authority_expiration_notifications()
        print(
            "Finished notifying subscribers about expiring certificate authority certificates! "
            f"Sent: {success} Failed: {failed}"
        )
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        capture_exception()

    metrics.send(
        "authority_expiration_notification_job", "counter", 1, metric_tags={"status": status}
    )


def security_expiration_summary(exclude):
    """
    Sends a summary email with info on all expiring certs (that match the configured expiry intervals).

    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("Starting to notify security team about expiring certificates!")
        success = send_security_expiration_summary(exclude)
        print(
            f"Finished notifying security team about expiring certificates! Success: {success}"
        )
        if success:
            status = SUCCESS_METRIC_STATUS
    except Exception:
        capture_exception()

    metrics.send(
        "security_expiration_notification_job", "counter", 1, metric_tags={"status": status}
    )


def notify_expiring_deployed_certificates(exclude):
    """
    Attempt to find any certificates that are expiring soon but are still deployed, and notify the certificate owner.
    This information is retrieved from the database, and is based on the previous run of
    identity_expiring_deployed_certificates.
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("Starting to notify owners about certificates that are expiring but still deployed!")
        certificates = get_expiring_deployed_certificates(exclude).items()
        success = send_expiring_deployed_certificate_notifications(certificates)
        print(
            f"Finished notifying owners about certificates that are expiring but still deployed! Success: {success}"
        )
        if success:
            status = SUCCESS_METRIC_STATUS
    except Exception:
        capture_exception()

    metrics.send(
        "notify_expiring_deployed_certificates_job", "counter", 1, metric_tags={"status": status}
    )
