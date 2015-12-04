"""
.. module: lemur.notifications
    :platform: Unix

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import ssl

import arrow

from flask import current_app
from lemur import database
from lemur.domains.models import Domain
from lemur.notifications.models import Notification
from lemur.certificates.models import Certificate

from lemur.certificates import service as cert_service

from lemur.plugins.base import plugins


def get_options(name, options):
    for o in options:
        if o.get('name') == name:
            return o


def _get_message_data(cert):
    """
    Parse our the certification information needed for our notification

    :param cert:
    :return:
    """
    cert_dict = {}

    if cert.user:
        cert_dict['creator'] = cert.user.email

    cert_dict['not_after'] = cert.not_after
    cert_dict['owner'] = cert.owner
    cert_dict['name'] = cert.name
    cert_dict['body'] = cert.body

    return cert_dict


def _deduplicate(messages):
    """
    Take all of the messages that should be sent and provide
    a roll up to the same set if the recipients are the same
    """
    roll_ups = []
    for data, options in messages:
        o = get_options('recipients', options)
        targets = o['value'].split(',')

        for m, r, o in roll_ups:
            if r == targets:
                for cert in m:
                    if cert['body'] == data['body']:
                        break
                else:
                    m.append(data)
                    current_app.logger.info(
                        "Sending expiration alert about {0} to {1}".format(
                            data['name'], ",".join(targets)))
                break
        else:
            roll_ups.append(([data], targets, options))

    return roll_ups


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
            for c in n.certificates:
                if _is_eligible_for_notifications(c):
                    messages.append((_get_message_data(c), n.options))

        messages = _deduplicate(messages)

        for data, targets, options in messages:
            sent += 1
            plugin.send('expiration', data, targets, options)

        current_app.logger.info("Lemur has sent {0} certification notifications".format(sent))
    return sent


def _get_domain_certificate(name):
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
    except Exception as e:
        current_app.logger.info(str(e))
        return []


def _find_superseded(cert):
    """
    Here we try to fetch any domain in the certificate to see if we can resolve it
    and to try and see if it is currently serving the certificate we are
    alerting on.

    :param domains:
    :return:
    """
    query = database.session_query(Certificate)
    ss_list = []

    # determine what is current host at our domains
    for domain in cert.domains:
        dups = _get_domain_certificate(domain.name)
        for c in dups:
            if c.body != cert.body:
                ss_list.append(dups)

        current_app.logger.info("Trying to resolve {0}".format(domain.name))

    # look for other certificates that may not be hosted but cover the same domains
    query = query.filter(Certificate.domains.any(Domain.name.in_([x.name for x in cert.domains])))
    query = query.filter(Certificate.active == True)  # noqa
    query = query.filter(Certificate.not_after >= arrow.utcnow().format('YYYY-MM-DD'))
    query = query.filter(Certificate.body != cert.body)
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
        interval = get_options('interval', notification.options)['value']
        unit = get_options('unit', notification.options)['value']
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
                plugin_name="email-notification",
                options=list(inter),
                description="Default {interval} day expiration notification".format(interval=i),
                certificates=[]
            )
        notifications.append(n)

    return notifications


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


def update(notification_id, label, options, description, active, certificates):
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
    notification.active = active
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
