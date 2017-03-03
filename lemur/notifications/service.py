"""
.. module: lemur.notifications.service
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from flask import current_app

from lemur import database
from lemur.certificates.models import Certificate
from lemur.notifications.models import Notification


def create_default_expiration_notifications(name, recipients):
    """
    Will create standard 30, 10 and 2 day notifications for a given owner. If standard notifications
    already exist these will be returned instead of new notifications.

    :param name:
    :param recipients:
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
    Retrieves an notification by its lemur assigned ID.

    :param notification_id: Lemur assigned ID
    :rtype : Notification
    :return:
    """
    return database.get(Notification, notification_id)


def get_by_label(label):
    """
    Retrieves a notification by its label

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
