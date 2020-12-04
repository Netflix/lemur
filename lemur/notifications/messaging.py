"""
.. module: lemur.notifications.messaging
    :platform: Unix

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import sys
from collections import defaultdict
from datetime import timedelta
from itertools import groupby

import arrow
from flask import current_app
from sqlalchemy import and_
from sqlalchemy.sql.expression import false, true

from lemur import database
from lemur.certificates import service as certificates_service
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.common.utils import windowed_query, is_selfsigned
from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS
from lemur.extensions import metrics, sentry
from lemur.pending_certificates.schemas import pending_certificate_output_schema
from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option


def get_certificates(exclude=None):
    """
    Finds all certificates that are eligible for expiration notifications.
    :param exclude:
    :return:
    """
    now = arrow.utcnow()
    max = now + timedelta(days=90)

    q = (
        database.db.session.query(Certificate)
        .filter(Certificate.not_after <= max)
        .filter(Certificate.notify == true())
        .filter(Certificate.expired == false())
        .filter(Certificate.revoked == false())
    )

    exclude_conditions = []
    if exclude:
        for e in exclude:
            exclude_conditions.append(~Certificate.name.ilike("%{}%".format(e)))

        q = q.filter(and_(*exclude_conditions))

    certs = []

    for c in windowed_query(q, Certificate.id, 10000):
        if needs_notification(c):
            certs.append(c)

    return certs


def get_expiring_authority_certificates():
    """
    Finds all certificate authority certificates that are eligible for expiration notifications.
    :return:
    """
    now = arrow.utcnow()
    authority_expiration_intervals = current_app.config.get("LEMUR_AUTHORITY_CERT_EXPIRATION_EMAIL_INTERVALS",
                                                            [365, 180])
    max_not_after = now + timedelta(days=max(authority_expiration_intervals) + 1)

    q = (
        database.db.session.query(Certificate)
        .filter(Certificate.not_after < max_not_after)
        .filter(Certificate.notify == true())
        .filter(Certificate.expired == false())
        .filter(Certificate.revoked == false())
        .filter(Certificate.root_authority_id.isnot(None))
        .filter(Certificate.authority_id.is_(None))
    )

    certs = []
    for c in windowed_query(q, Certificate.id, 10000):
        days_remaining = (c.not_after - now).days
        if days_remaining in authority_expiration_intervals:
            certs.append(c)
    return certs


def get_eligible_certificates(exclude=None):
    """
    Finds all certificates that are eligible for certificate expiration notification.
    Returns the set of all eligible certificates, grouped by owner, with a list of applicable notifications.
    :param exclude:
    :return:
    """
    certificates = defaultdict(dict)
    certs = get_certificates(exclude=exclude)

    # group by owner
    for owner, items in groupby(certs, lambda x: x.owner):
        notification_groups = []

        for certificate in items:
            notifications = needs_notification(certificate)

            if notifications:
                for notification in notifications:
                    notification_groups.append((notification, certificate))

        # group by notification
        for notification, items in groupby(notification_groups, lambda x: x[0].label):
            certificates[owner][notification] = list(items)

    return certificates


def get_eligible_authority_certificates():
    """
    Finds all certificate authority certificates that are eligible for certificate expiration notification.
    Returns the set of all eligible CA certificates, grouped by owner and interval, with a list of applicable certs.
    :return:
    """
    certificates = defaultdict(dict)
    all_certs = get_expiring_authority_certificates()
    now = arrow.utcnow()

    # group by owner
    for owner, owner_certs in groupby(all_certs, lambda x: x.owner):
        # group by expiration interval
        for interval, interval_certs in groupby(owner_certs, lambda x: (x.not_after - now).days):
            certificates[owner][interval] = list(interval_certs)

    return certificates


def send_plugin_notification(event_type, data, recipients, notification):
    """
    Executes the plugin and handles failure.

    :param event_type:
    :param data:
    :param recipients:
    :param notification:
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    log_data = {
        "function": function,
        "message": f"Sending {event_type} notification for to recipients {recipients}",
        "notification_type": event_type,
        "notification_plugin": notification.plugin.slug,
        "certificate_targets": recipients,
    }
    status = FAILURE_METRIC_STATUS
    try:
        current_app.logger.debug(log_data)
        notification.plugin.send(event_type, data, recipients, notification.options)
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        log_data["message"] = f"Unable to send {event_type} notification to recipients {recipients}"
        current_app.logger.error(log_data, exc_info=True)
        sentry.captureException()

    metrics.send(
        "notification",
        "counter",
        1,
        metric_tags={"status": status, "event_type": event_type, "plugin": notification.plugin.slug},
    )

    if status == SUCCESS_METRIC_STATUS:
        return True


def send_expiration_notifications(exclude):
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    success = failure = 0

    # security team gets all
    security_email = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")

    for owner, notification_group in get_eligible_certificates(exclude=exclude).items():

        for notification_label, certificates in notification_group.items():
            notification_data = []

            notification = certificates[0][0]

            for data in certificates:
                n, certificate = data
                cert_data = certificate_notification_output_schema.dump(
                    certificate
                ).data
                notification_data.append(cert_data)

            email_recipients = notification.plugin.get_recipients(notification.options, security_email + [owner])
            # Plugin will ONLY use the provided recipients if it's email; any other notification plugin ignores them
            if send_plugin_notification(
                    "expiration", notification_data, email_recipients, notification
            ):
                success += len(email_recipients)
            else:
                failure += len(email_recipients)
            # If we're using an email plugin, we're done,
            #   since "security_email + [owner]" were added as email_recipients.
            # If we're not using an email plugin, we also need to send an email to the security team and owner,
            #   since the plugin notification didn't send anything to them.
            if notification.plugin.slug != "email-notification":
                if send_default_notification(
                        "expiration", notification_data, email_recipients, notification.options
                ):
                    success = 1 + len(email_recipients)
                else:
                    failure = 1 + len(email_recipients)

    return success, failure


def send_authority_expiration_notifications():
    """
    This function will check for upcoming certificate authority certificate expiration,
    and send out notification emails at configured intervals.
    """
    success = failure = 0

    # security team gets all
    security_email = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")

    for owner, owner_cert_groups in get_eligible_authority_certificates().items():
        for interval, certificates in owner_cert_groups.items():
            notification_data = []

            for certificate in certificates:
                cert_data = certificate_notification_output_schema.dump(
                    certificate
                ).data
                cert_data['self_signed'] = is_selfsigned(certificate.parsed_cert)
                cert_data['issued_cert_count'] = certificates_service.get_issued_cert_count_for_authority(certificate.root_authority)
                notification_data.append(cert_data)

            email_recipients = security_email + [owner]
            if send_default_notification(
                    "authority_expiration", notification_data, email_recipients,
                    notification_options=[{'name': 'interval', 'value': interval}]
            ):
                success = len(email_recipients)
            else:
                failure = len(email_recipients)

    return success, failure


def send_default_notification(notification_type, data, targets, notification_options=None):
    """
    Sends a report to the specified target via the default notification plugin. Applicable for any notification_type.
    At present, "default" means email, as the other notification plugins do not support dynamically configured targets.

    :param notification_type:
    :param data:
    :param targets:
    :param notification_options:
    :return:
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"
    status = FAILURE_METRIC_STATUS
    notification_plugin = plugins.get(
        current_app.config.get("LEMUR_DEFAULT_NOTIFICATION_PLUGIN", "email-notification")
    )
    log_data = {
        "function": function,
        "message": f"Sending {notification_type} notification for certificate data {data} to targets {targets}",
        "notification_type": notification_type,
        "notification_plugin": notification_plugin.slug,
    }

    try:
        current_app.logger.debug(log_data)
        # we need the notification.options here because the email templates utilize the interval/unit info
        notification_plugin.send(notification_type, data, targets, notification_options)
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        log_data["message"] = f"Unable to send {notification_type} notification for certificate data {data} " \
                              f"to targets {targets}"
        current_app.logger.error(log_data, exc_info=True)
        sentry.captureException()

    metrics.send(
        "notification",
        "counter",
        1,
        metric_tags={"status": status, "event_type": notification_type, "plugin": notification_plugin.slug},
    )

    if status == SUCCESS_METRIC_STATUS:
        return True


def send_rotation_notification(certificate):
    data = certificate_notification_output_schema.dump(certificate).data
    return send_default_notification("rotation", data, [data["owner"]])


def send_pending_failure_notification(
    pending_cert, notify_owner=True, notify_security=True
):
    """
    Sends a report to certificate owners when their pending certificate failed to be created.

    :param pending_cert:
    :param notify_owner:
    :param notify_security:
    :return:
    """

    data = pending_certificate_output_schema.dump(pending_cert).data
    data["security_email"] = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")

    email_recipients = []
    if notify_owner:
        email_recipients = email_recipients + [data["owner"]]

    if notify_security:
        email_recipients = email_recipients + data["security_email"]

    return send_default_notification("failed", data, email_recipients, pending_cert)


def needs_notification(certificate):
    """
    Determine if notifications for a given certificate should currently be sent.
    For each notification configured for the cert, verifies it is active, properly configured,
    and that the configured expiration period is currently met.

    :param certificate:
    :return:
    """
    now = arrow.utcnow()
    days = (certificate.not_after - now).days

    notifications = []

    for notification in certificate.notifications:
        if not notification.active or not notification.options:
            continue

        interval = get_plugin_option("interval", notification.options)
        unit = get_plugin_option("unit", notification.options)

        if unit == "weeks":
            interval *= 7

        elif unit == "months":
            interval *= 30

        elif unit == "days":  # it's nice to be explicit about the base unit
            pass

        else:
            raise Exception(
                f"Invalid base unit for expiration interval: {unit}"
            )
        if days == interval:
            notifications.append(notification)
    return notifications
