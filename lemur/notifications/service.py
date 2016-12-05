"""
.. module: lemur.notifications
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import arrow

from flask import current_app

from lemur import database
from lemur.extensions import metrics
from lemur.plugins.base import plugins
from lemur.plugins.utils import get_plugin_option

from lemur.notifications.models import Notification
from lemur.certificates.models import Certificate

from lemur.certificates.schemas import certificate_notification_output_schema


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    for plugin in plugins.all(plugin_type='notification'):
        notifications = database.db.session.query(Notification)\
            .filter(Notification.plugin_name == plugin.slug)\
            .filter(Notification.active == True).all()  # noqa

        messages = []
        for n in notifications:
            for certificate in n.certificates:
                if _is_eligible_for_notifications(certificate):
                    data = certificate_notification_output_schema.dump(certificate).data
                    messages.append((data, n.options))

        for data, targets, options in messages:
            try:
                plugin.send('expiration', data, targets, options)
                metrics.send('expiration_notification_sent', 'counter', 1)
            except Exception as e:
                metrics.send('expiration_notification_failure', 'counter', 1)
                current_app.logger.exception(e)


def send_rotation_notifications(certificates):
    """
    Sends a report to certificate owners when their certificate as been
    rotated.
    :return:
    """
    plugin = plugins.get(current_app.config.get('LEMUR_DEFAULT_NOTIFICATION_PLUGIN'))

    messages = {}

    for certificate in certificates:
        data = certificate_notification_output_schema.dump(certificate).data

        if data.owner in messages.keys():
            messages[data.owner].append(data)
        else:
            messages[data.owner] = [data]

        for owner, data in messages:
            try:
                plugin.send('rotation', data, [owner])
                metrics.send('rotation_notification_sent', 'counter', 1)
            except Exception as e:
                metrics.send('rotation_notification_failure', 'counter', 1)
                current_app.logger.exception(e)


def _is_eligible_for_notifications(cert):
    """
    Determine if notifications for a given certificate should
    currently be sent

    :param cert:
    :return:
    """
    if not cert.notify:
        return

    now = arrow.utcnow()
    days = (cert.not_after - now.naive).days

    for notification in cert.notifications:
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
            return cert


def create_default_expiration_notifications(name, recipients):
    """
    Will create standard 30, 10 and 2 day notifications for a given owner. If standard notifications
    already exist these will be returned instead of new notifications.

    :param name:
    :return:
    """
    if not recipients:
        return []

    options = [
        {
            'name': 'unit',
            'type': 'select',
            'required': True,
            'validation': '',
            'available': ['days', 'weeks', 'months'],
            'helpMessage': 'Interval unit',
            'value': 'days',
        },
        {
            'name': 'recipients',
            'type': 'str',
            'required': True,
            'validation': '^([\w+-.%]+@[\w-.]+\.[A-Za-z]{2,4},?)+$',
            'helpMessage': 'Comma delimited list of email addresses',
            'value': ','.join(recipients)
        },
    ]

    intervals = current_app.config.get("LEMUR_DEFAULT_EXPIRATION_NOTIFICATION_INTERVALS", [30, 15, 2])

    notifications = []
    for i in intervals:
        n = get_by_label("{name}_{interval}_DAY".format(name=name, interval=i))
        if not n:
            inter = [
                {
                    'name': 'interval',
                    'type': 'int',
                    'required': True,
                    'validation': '^\d+$',
                    'helpMessage': 'Number of days to be alert before expiration.',
                    'value': i,
                }
            ]
            inter.extend(options)
            n = create(
                label="{name}_{interval}_DAY".format(name=name, interval=i),
                plugin_name=current_app.config.get("LEMUR_DEFAULT_NOTIFICATION_PLUGIN", "email-notification"),
                options=list(inter),
                description="Default {interval} day expiration notification".format(interval=i),
                certificates=[]
            )
        notifications.append(n)

    return notifications


def create(label, plugin_name, options, description, certificates):
    """
    Creates a new notification.

    :param label: Notification label
    :param plugin_name:
    :param options:
    :param description:
    :param certificates:
    :rtype : Notification
    :return:
    """
    notification = Notification(label=label, options=options, plugin_name=plugin_name, description=description)
    notification.certificates = certificates
    return database.create(notification)


def update(notification_id, label, options, description, active, certificates):
    """
    Updates an existing notification.

    :param notification_id:
    :param label: Notification label
    :param options:
    :param description:
    :param active:
    :param certificates:
    :rtype : Notification
    :return:
    """
    notification = get(notification_id)

    notification.label = label
    notification.options = options
    notification.description = description
    notification.active = active
    notification.certificates = certificates

    return database.update(notification)


def delete(notification_id):
    """
    Deletes an notification.

    :param notification_id: Lemur assigned ID
    """
    database.delete(get(notification_id))


def get(notification_id):
    """
    Retrieves an notification by it's lemur assigned ID.

    :param notification_id: Lemur assigned ID
    :rtype : Notification
    :return:
    """
    return database.get(Notification, notification_id)


def get_by_label(label):
    """
    Retrieves a notification by it's label

    :param label:
    :return:
    """
    return database.get(Notification, label, field='label')


def get_all():
    """
    Retrieves all notification currently known by Lemur.

    :return:
    """
    query = database.session_query(Notification)
    return database.find_all(query, Notification, {}).all()


def render(args):
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if certificate_id:
        query = database.session_query(Notification).join(Certificate, Notification.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Notification)

    if filt:
        terms = filt.split(';')
        if terms[0] == 'active' and terms[1] == 'false':
            query = query.filter(Notification.active == False)  # noqa
        elif terms[0] == 'active' and terms[1] == 'true':
            query = query.filter(Notification.active == True)  # noqa
        else:
            query = database.filter(query, Notification, terms)

    return database.sort_and_page(query, Notification, args)
