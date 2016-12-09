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
from flask import current_app

from lemur import database, metrics
from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.certificates.models import Certificate

from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option


def get_certificates():
    """
    Finds all certificates that are eligible for notifications.
    :return:
    """
    return database.session_query(Certificate)\
        .filter(Certificate.notify == True)\
        .filter(Certificate.expired == False)\
        .filter(Certificate.notifications.any()).all()  # noqa


def get_eligible_certificates():
    """
    Finds all certificates that are eligible for certificate expiration.
    :return:
    """
    certificates = defaultdict(list)

    for owner, items in groupby(get_certificates(), lambda x: x.owner):
        notification_groups = []

        for certificate in items:
            notification = needs_notification(certificate)

            if notification:
                notification_groups.append((certificate, notification))

        certificates[owner].extend(notification_groups)

    return certificates


def send_notification(event_type, data, targets, options, slug):
    """
    Executes the plugin and handles failure.

    :param event_type:
    :param data:
    :param targets:
    :param options:
    :return:
    """
    plugin = plugins.get(slug)
    try:
        plugin.send(event_type, data, targets, options)
        metrics.send('{0}_notification_sent'.format(event_type), 'counter', 1)

    except Exception as e:
        metrics.send('{0}_notification_failure'.format(event_type), 'counter', 1)
        current_app.logger.exception(e)


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    # security team gets all
    security_email = current_app.config.get('LEMUR_SECURITY_EMAIL')

    security_data = []
    for owner, notification_group in get_eligible_certificates().items():

        for certificates, notification in notification_group.items():
            notification_data = []

            for certificate in certificates:
                cert_data = certificate_notification_output_schema.dump(certificate).data
                notification_data.append(cert_data)
                security_data.append(cert_data)

            send_notification('expiration', notification_data, [owner], notification.options)

    send_notification('expiration', security_data, [security_email], None)


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
