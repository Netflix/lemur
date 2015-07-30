"""
.. module: lemur.plugins.lemur_aws.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import boto.ses
from flask import current_app
from flask_mail import Message

from lemur.extensions import smtp_mail

from lemur.plugins.bases import ExpirationNotificationPlugin
from lemur.plugins import lemur_email as email


from lemur.plugins.lemur_email.templates.config import env


def find_value(name, options):
    for o in options:
        if o.get(name):
            return o['value']


class EmailNotificationPlugin(ExpirationNotificationPlugin):
    title = 'Email'
    slug = 'email-notification'
    description = 'Sends expiration email notifications'
    version = email.VERSION

    author = 'Kevin Glisson'
    author_url = 'https://github.com/netflix/lemur'

    additional_options = [
        {
            'name': 'recipients',
            'type': 'str',
            'required': True,
            'validation': '^([\w+-.%]+@[\w-.]+\.[A-Za-z]{2,4},?)+$',
            'helpMessage': 'Comma delimited list of email addresses',
        },
    ]

    @staticmethod
    def send(event_type, message, targets, options, **kwargs):
        """
        Configures all Lemur email messaging

        :param event_type:
        :param options:
        """
        subject = 'Notification: Lemur'

        if event_type == 'expiration':
            subject = 'Notification: SSL Certificate Expiration '

        # jinja template depending on type
        template = env.get_template('{}.html'.format(event_type))
        body = template.render(**kwargs)

        s_type = current_app.config.get("LEMUR_EMAIL_SENDER").lower()
        if s_type == 'ses':
            conn = boto.connect_ses()
            conn.send_email(current_app.config.get("LEMUR_EMAIL"), subject, body, targets, format='html')

        elif s_type == 'smtp':
            msg = Message(subject, recipients=targets)
            msg.body = ""  # kinda a weird api for sending html emails
            msg.html = body
            smtp_mail.send(msg)

        else:
            current_app.logger.error("No mail carrier specified, notification emails were not able to be sent!")
