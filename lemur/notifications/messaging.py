"""
.. module: lemur.notifications.messaging
    :platform: Unix

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from collections import defaultdict
from datetime import timedelta
from itertools import groupby

import arrow
from flask import current_app
from sqlalchemy import and_

from lemur import database
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.common.utils import windowed_query
from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS
from lemur.extensions import metrics, sentry
from lemur.pending_certificates.schemas import pending_certificate_output_schema
from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option


def get_certificates(exclude=None):
    """
    Finds all certificates that are eligible for notifications.
    :param exclude:
    :return:
    """
    now = arrow.utcnow()
    max = now + timedelta(days=90)

    q = (
        database.db.session.query(Certificate)
        .filter(Certificate.not_after <= max)
        .filter(Certificate.notify == True)
        .filter(Certificate.expired == False)
    )  # noqa

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


def get_eligible_certificates(exclude=None):
    """
    Finds all certificates that are eligible for certificate expiration.
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


def send_notification(event_type, data, targets, notification):
    """
    Executes the plugin and handles failure.

    :param event_type:
    :param data:
    :param targets:
    :param notification:
    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        notification.plugin.send(event_type, data, targets, notification.options)
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        sentry.captureException()

    metrics.send(
        "notification",
        "counter",
        1,
        metric_tags={"status": status, "event_type": event_type},
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

    security_data = []
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
                security_data.append(cert_data)

            if send_notification(
                "expiration", notification_data, [owner], notification
            ):
                success += 1
            else:
                failure += 1

            notification_recipient = get_plugin_option(
                "recipients", notification.options
            )
            if notification_recipient:
                notification_recipient = notification_recipient.split(",")
                # removing owner and security_email from notification_recipient
                notification_recipient = [i for i in notification_recipient if i not in security_email and i != owner]

            if (
                notification_recipient
            ):
                if send_notification(
                    "expiration",
                    notification_data,
                    notification_recipient,
                    notification,
                ):
                    success += 1
                else:
                    failure += 1

            if send_notification(
                "expiration", security_data, security_email, notification
            ):
                success += 1
            else:
                failure += 1

    return success, failure


def send_rotation_notification(certificate, notification_plugin=None):
    """
    Sends a report to certificate owners when their certificate has been
    rotated.

    :param certificate:
    :param notification_plugin:
    :return:
    """
    status = FAILURE_METRIC_STATUS
    if not notification_plugin:
        notification_plugin = plugins.get(
            current_app.config.get("LEMUR_DEFAULT_NOTIFICATION_PLUGIN")
        )

    data = certificate_notification_output_schema.dump(certificate).data

    try:
        notification_plugin.send("rotation", data, [data["owner"]])
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        current_app.logger.error(
            "Unable to send notification to {}.".format(data["owner"]), exc_info=True
        )
        sentry.captureException()

    metrics.send(
        "notification",
        "counter",
        1,
        metric_tags={"status": status, "event_type": "rotation"},
    )

    if status == SUCCESS_METRIC_STATUS:
        return True


def send_pending_failure_notification(
    pending_cert, notify_owner=True, notify_security=True, notification_plugin=None
):
    """
    Sends a report to certificate owners when their pending certificate failed to be created.

    :param pending_cert:
    :param notification_plugin:
    :return:
    """
    status = FAILURE_METRIC_STATUS

    if not notification_plugin:
        notification_plugin = plugins.get(
            current_app.config.get(
                "LEMUR_DEFAULT_NOTIFICATION_PLUGIN", "email-notification"
            )
        )

    data = pending_certificate_output_schema.dump(pending_cert).data
    data["security_email"] = current_app.config.get("LEMUR_SECURITY_TEAM_EMAIL")

    if notify_owner:
        try:
            notification_plugin.send("failed", data, [data["owner"]], pending_cert)
            status = SUCCESS_METRIC_STATUS
        except Exception as e:
            current_app.logger.error(
                "Unable to send pending failure notification to {}.".format(
                    data["owner"]
                ),
                exc_info=True,
            )
            sentry.captureException()

    if notify_security:
        try:
            notification_plugin.send(
                "failed", data, data["security_email"], pending_cert
            )
            status = SUCCESS_METRIC_STATUS
        except Exception as e:
            current_app.logger.error(
                "Unable to send pending failure notification to "
                "{}.".format(data["security_email"]),
                exc_info=True,
            )
            sentry.captureException()

    metrics.send(
        "notification",
        "counter",
        1,
        metric_tags={"status": status, "event_type": "rotation"},
    )

    if status == SUCCESS_METRIC_STATUS:
        return True


def needs_notification(certificate):
    """
    Determine if notifications for a given certificate should
    currently be sent

    :param certificate:
    :return:
    """
    now = arrow.utcnow()
    days = (certificate.not_after - now).days

    notifications = []

    for notification in certificate.notifications:
        if not notification.active or not notification.options:
            return

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
                "Invalid base unit for expiration interval: {0}".format(unit)
            )

        if days == interval:
            notifications.append(notification)
    return notifications
