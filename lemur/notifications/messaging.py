"""
.. module: lemur.notifications.messaging
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""

import arrow
from flask import current_app

from lemur import database, metrics
from lemur.certificates.schemas import certificate_notification_output_schema
from lemur.notifications.models import Notification
from lemur.plugins import plugins
from lemur.plugins.utils import get_plugin_option


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    sent = 0
    for plugin in plugins.all(plugin_type='notification'):
        notifications = database.db.session.query(Notification)\
            .filter(Notification.plugin_name == plugin.slug)\
            .filter(Notification.active == True).all()  # noqa

        messages = []
        for n in notifications:
            for certificate in n.certificates:
                if needs_notification(certificate):
                    data = certificate_notification_output_schema.dump(certificate).data
                    messages.append((data, n.options))

        for data, options in messages:
            try:
                plugin.send('expiration', data, [data['owner']], options)
                metrics.send('expiration_notification_sent', 'counter', 1)
                sent += 1
            except Exception as e:
                metrics.send('expiration_notification_failure', 'counter', 1)
                current_app.logger.exception(e)
    return sent


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
    if not certificate.notify:
        return

    if not certificate.notifications:
        return

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
            return certificate
