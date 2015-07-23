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
import boto.ses

from flask import current_app
from flask_mail import Message

from lemur import database
from lemur.certificates.models import Certificate
from lemur.domains.models import Domain

from lemur.templates.config import env
from lemur.extensions import smtp_mail


NOTIFICATION_INTERVALS = [30, 15, 5, 2]


def _get_domain_certificate(name):
    """
    Fetch the SSL certificate currently hosted at a given domain (if any) and
    compare it against our all of our know certificates to determine if a new
    SSL certificate has already been deployed

    :param name:
    :return:
    """
    query = database.session_query(Certificate)
    try:
        pub_key = ssl.get_server_certificate((name, 443))
        return query.filter(Certificate.body == pub_key.strip()).first()

    except socket.gaierror as e:
        current_app.logger.info(str(e))


def _find_superseded(domains):
    """
    Here we try to fetch any domain in the certificate to see if we can resolve it
    and to try and see if it is currently serving the certificate we are
    alerting on

    :param domains:
    :return:
    """
    query = database.session_query(Certificate)
    ss_list = []
    for domain in domains:
        dc = _get_domain_certificate(domain.name)
        if dc:
            ss_list.append(dc)
        current_app.logger.info("Trying to resolve {0}".format(domain.name))

    query = query.filter(Certificate.domains.any(Domain.name.in_([x.name for x in domains])))
    query = query.filter(Certificate.active == True)  # noqa
    query = query.filter(Certificate.not_after >= arrow.utcnow().format('YYYY-MM-DD'))
    ss_list.extend(query.all())

    return ss_list


def send_expiration_notifications():
    """
    This function will check for upcoming certificate expiration,
    and send out notification emails at given intervals.
    """
    notifications = 0
    certs = _get_expiring_certs()

    alerts = []
    for cert in certs:
        if _is_eligible_for_notifications(cert):
            data = _get_message_data(cert)
            recipients = _get_message_recipients(cert)
            alerts.append((data, recipients))

    roll_ups = _create_roll_ups(alerts)

    for messages, recipients in roll_ups:
        notifications += 1
        send("Certificate Expiration", dict(messages=messages), 'event', recipients)

    print notifications
    current_app.logger.info("Lemur has sent {0} certification notifications".format(notifications))


def _get_message_recipients(cert):
    """
    Determine who the recipients of the certificate expiration should be

    :param cert:
    :return:
    """
    recipients = []
    if current_app.config.get('SECURITY_TEAM_EMAIL'):
        recipients.extend(current_app.config.get('SECURITY_TEAM_EMAIL'))

    recipients.append(cert.owner)

    if cert.user:
        recipients.append(cert.user.email)
    return list(set(recipients))


def _get_message_data(cert):
    """
    Parse our the certification information needed for our notification

    :param cert:
    :return:
    """
    cert_dict = cert.as_dict()
    cert_dict['domains'] = [x .name for x in cert.domains]
    cert_dict['superseded'] = list(set([x.name for x in _find_superseded(cert.domains) if cert.name != x]))
    return cert_dict


def _get_expiring_certs(outlook=30):
    """
    Find all the certificates expiring within a given outlook

    :param outlook: int days to look forward
    :return:
    """
    now = arrow.utcnow()

    query = database.session_query(Certificate)
    attr = Certificate.not_after

    # get all certs expiring in the next 30 days
    to = now.replace(days=+outlook).format('YYYY-MM-DD')

    certs = []
    for cert in query.filter(attr <= to).filter(attr >= now.format('YYYY-MM-DD')).all():
        if _is_eligible_for_notifications(cert):
            certs.append(cert)
    return certs


def _is_eligible_for_notifications(cert, intervals=None):
    """
    Determine if notifications for a given certificate should
    currently be sent

    :param cert:
    :param intervals: list of days to alert on
    :return:
    """
    now = arrow.utcnow()
    if cert.active:
        days = (cert.not_after - now.naive).days

        if not intervals:
            intervals = NOTIFICATION_INTERVALS

        if days in intervals:
            return cert


def _create_roll_ups(messages):
    """
    Take all of the messages that should be sent and provide
    a roll up to the same set if the recipients are the same

    :param messages:
    """
    roll_ups = []
    for message_data, recipients in messages:
        for m, r in roll_ups:
            if r == recipients:
                m.append(message_data)
                current_app.logger.info(
                    "Sending email expiration alert about {0} to {1}".format(
                        message_data['name'], ",".join(recipients)))
                break
        else:
            roll_ups.append(([message_data], recipients))
    return roll_ups


def send(subject, data, email_type, recipients):
    """
    Configures all Lemur email messaging

    :param subject:
    :param data:
    :param email_type:
    :param recipients:
    """
    # jinja template depending on type
    template = env.get_template('{}.html'.format(email_type))
    body = template.render(**data)

    s_type = current_app.config.get("LEMUR_EMAIL_SENDER").lower()
    if s_type == 'ses':
        conn = boto.connect_ses()
        conn.send_email(current_app.config.get("LEMUR_EMAIL"), subject, body, recipients, format='html')

    elif s_type == 'smtp':
        msg = Message(subject, recipients=recipients)
        msg.body = ""  # kinda a weird api for sending html emails
        msg.html = body
        smtp_mail.send(msg)

    else:
        current_app.logger.error("No mail carrier specified, notification emails were not able to be sent!")
