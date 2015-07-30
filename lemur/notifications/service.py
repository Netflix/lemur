"""
.. module: lemur.notifications
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import ssl
import socket

import arrow

from flask import current_app
from lemur import database
from lemur.domains.models import Domain
from lemur.notifications.models import Notification
from lemur.certificates.models import Certificate

from lemur.certificates import service as cert_service

from lemur.plugins.base import plugins


def _get_message_data(cert):
    """
    Parse our the certification information needed for our notification

    :param cert:
    :return:
    """
    cert_dict = cert.as_dict()
    cert_dict['creator'] = cert.user.email
    cert_dict['domains'] = [x .name for x in cert.domains]
    cert_dict['superseded'] = list(set([x.name for x in find_superseded(cert.domains) if cert.name != x]))
    return cert_dict


def _deduplicate(messages):
    """
    Take all of the messages that should be sent and provide
    a roll up to the same set if the recipients are the same
    """
    roll_ups = []
    for targets, data in messages:
        for m, r in roll_ups:
            if r == targets:
                m.append(data)
                current_app.logger.info(
                    "Sending expiration alert about {0} to {1}".format(
                        data['name'], ",".join(targets)))
                break
        else:
            roll_ups.append(([data], targets, data.plugin_options))
    return roll_ups


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    notifications = 0

    for plugin_name, notifications in database.get_all(Notification, 'active', field='status').group_by(Notification.plugin_name):
        notifications += 1

        messages = _deduplicate(notifications)
        plugin = plugins.get(plugin_name)

        for data, targets, options in messages:
            plugin.send('expiration', data, targets, options)

    current_app.logger.info("Lemur has sent {0} certification notifications".format(notifications))


def get_domain_certificate(name):
    """
    Fetch the SSL certificate currently hosted at a given domain (if any) and
    compare it against our all of our know certificates to determine if a new
    SSL certificate has already been deployed

    :param name:
    :return:
    """
    try:
        pub_key = ssl.get_server_certificate((name, 443))
        return cert_service.find_duplicates(pub_key.strip())
    except socket.gaierror as e:
        current_app.logger.info(str(e))


def find_superseded(domains):
    """
    Here we try to fetch any domain in the certificate to see if we can resolve it
    and to try and see if it is currently serving the certificate we are
    alerting on.

    :param domains:
    :return:
    """
    query = database.session_query(Certificate)
    ss_list = []
    for domain in domains:
        dc = get_domain_certificate(domain.name)
        if dc:
            ss_list.append(dc)
        current_app.logger.info("Trying to resolve {0}".format(domain.name))

    query = query.filter(Certificate.domains.any(Domain.name.in_([x.name for x in domains])))
    query = query.filter(Certificate.active == True)  # noqa
    query = query.filter(Certificate.not_after >= arrow.utcnow().format('YYYY-MM-DD'))
    ss_list.extend(query.all())

    return ss_list


def _is_eligible_for_notifications(cert):
    """
    Determine if notifications for a given certificate should
    currently be sent

    :param cert:
    :return:
    """
    now = arrow.utcnow()
    days = (cert.not_after - now.naive).days

    for notification in cert.notifications:
        interval = notification.options['interval']
        unit = notification.options['unit']
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


def create(label, plugin_name, options, description, certificates):
    """
    Creates a new destination, that can then be used as a destination for certificates.

    :param label: Notification common name
    :param plugin_name:
    :param options:
    :param description:
    :rtype : Notification
    :return:
    """
    notification = Notification(label=label, options=options, plugin_name=plugin_name, description=description)
    notification = database.update_list(notification, 'certificates', Certificate, certificates)
    return database.create(notification)


def update(notification_id, label, options, description, certificates):
    """
    Updates an existing destination.

    :param label: Notification common name
    :param options:
    :param description:
    :rtype : Notification
    :return:
    """
    notification = get(notification_id)

    notification.label = label
    notification.options = options
    notification.description = description
    notification = database.update_list(notification, 'certificates', Certificate, certificates)

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
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
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

    query = database.find_all(query, Notification, args)

    if sort_by and sort_dir:
        query = database.sort(query, Notification, sort_by, sort_dir)

    return database.paginate(query, page, count)
