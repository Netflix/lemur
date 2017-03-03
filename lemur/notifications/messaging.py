"""
.. module: lemur.notifications.messaging
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from itertools import groupby
from collections import defaultdict

import arrow
from datetime import timedelta
from flask import current_app

from lemur import database, metrics
from lemur.common.utils import windowed_query

from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.certificates.models import Certificate

from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option


def get_certificates():
    """
    Finds all certificates that are eligible for notifications.
    :return:
    """
    now = arrow.utcnow()
    max = now + timedelta(days=90)

    q = database.db.session.query(Certificate) \
        .filter(Certificate.not_after <= max) \
        .filter(Certificate.notify == True) \
        .filter(Certificate.expired == False)  # noqa

    certs = []

    for c in windowed_query(q, Certificate.id, 100):
        if needs_notification(c):
            certs.append(c)

    return certs


def get_eligible_certificates():
    """
    Finds all certificates that are eligible for certificate expiration.
    :return:
    """
    certificates = defaultdict(dict)
    certs = get_certificates()

    # group by owner
    for owner, items in groupby(certs, lambda x: x.owner):
        notification_groups = []

        for certificate in items:
            notification = needs_notification(certificate)

            if notification:
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
    try:
        notification.plugin.send(event_type, data, targets, notification.options)
        metrics.send('{0}_notification_sent'.format(event_type), 'counter', 1)
        return True
    except Exception as e:
        metrics.send('{0}_notification_failure'.format(event_type), 'counter', 1)
        current_app.logger.exception(e)


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    success = failure = 0

    # security team gets all
    security_email = current_app.config.get('LEMUR_SECURITY_TEAM_EMAIL')

    security_data = []
    for owner, notification_group in get_eligible_certificates().items():

        for notification_label, certificates in notification_group.items():
            notification_data = []

            notification = certificates[0][0]

            for data in certificates:
                n, certificate = data
                cert_data = certificate_notification_output_schema.dump(certificate).data
                notification_data.append(cert_data)
                security_data.append(cert_data)

            if send_notification('expiration', notification_data, [owner], notification):
                success += 1
            else:
                failure += 1

    if send_notification('expiration', security_data, security_email, notification):
        success += 1
    else:
        failure += 1

    return success, failure


def send_rotation_notification(certificate, notification_plugin=None):
    """
    Sends a report to certificate owners when their certificate as been
    rotated.

    :param certificate:
    :return:
    """
    if not notification_plugin:
        notification_plugin = plugins.get(current_app.config.get('LEMUR_DEFAULT_NOTIFICATION_PLUGIN'))

    data = certificate_notification_output_schema.dump(certificate).data

    try:
        notification_plugin.send('rotation', data, [data['owner']])
        metrics.send('rotation_notification_sent', 'counter', 1)
        return True
    except Exception as e:
        metrics.send('rotation_notification_failure', 'counter', 1)
        current_app.logger.exception(e)


def needs_notification(certificate):
    """
    Determine if notifications for a given certificate should
    currently be sent

    :param certificate:
    :return:
    """
    now = arrow.utcnow()
    days = (certificate.not_after - now).days

    for notification in certificate.notifications:
        if not notification.options:
            return

        interval = get_plugin_option('interval', notification.options)
        unit = get_plugin_option('unit', notification.options)

        if unit == 'weeks':
            interval *= 7

        elif unit == 'months':
            interval *= 30

        elif unit == 'days':  # it's nice to be explicit about the base unit
            pass

        else:
            raise Exception("Invalid base unit for expiration interval: {0}".format(unit))

        if days == interval:
            return notification
