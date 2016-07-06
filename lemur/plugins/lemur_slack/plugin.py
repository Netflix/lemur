"""
.. module: lemur.plugins.lemur_slack.slack
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Harm Weites <harm@weites.com>
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json
import arrow
from flask import current_app
from lemur.plugins.bases import ExpirationNotificationPlugin
from lemur.plugins import lemur_slack as slack

import requests


def create_certificate_url(name):
    return 'https://{{ hostname }}/#/certificates/{{ name }}'.format(
        hostname=current_app.config.get('LEMUR_HOSTNAME'),
        name=name
    )


def create_expiration_attachments(messages):
    attachments = []
    for message in messages:
        attachments.append({
            'title': message['name'],
            'title_link': create_certificate_url(message['name']),
            'color': 'danger',
            'fallback': '',
            'fields': [
                {
                    'title': 'Owner',
                    'value': message['owner'],
                    'short': True
                },
                {
                    'title': 'Expires',
                    'value': arrow.get(message['not_after']).format('dddd, MMMM D, YYYY'),
                    'short': True
                },
                {
                    'title': 'Endpoints Detected',
                    'value': len(message['endpoints']),
                    'short': True
                }
            ],
            'text': '',
            'mrkdwn_in': ['text']
        })
    return attachments


class SlackNotificationPlugin(ExpirationNotificationPlugin):
    title = 'Slack'
    slug = 'slack-notification'
    description = 'Sends notifications to Slack'
    version = slack.VERSION

    author = 'Harm Weites'
    author_url = 'https://github.com/netflix/lemur'

    additional_options = [
        {
            'name': 'webhook',
            'type': 'str',
            'required': True,
            'validation': '^https:\/\/hooks\.slack\.com\/services\/.+$',
            'helpMessage': 'The url Slack told you to use for this integration',
        }, {
            'name': 'username',
            'type': 'str',
            'validation': '^.+$',
            'helpMessage': 'The great storyteller',
            'default': 'Lemur'
        }, {
            'name': 'recipients',
            'type': 'str',
            'required': True,
            'validation': '^(@|#).+$',
            'helpMessage': 'Where to send to, either @username or #channel',
        },
    ]

    def send(self, event_type, message, targets, options, **kwargs):
        """
        A typical check can be performed using the notify command:
        `lemur notify`
        """
        if event_type == 'expiration':
            attachments = create_expiration_attachments(message)

        if not attachments:
            raise Exception('Unable to create message attachments')

        body = {
            'text': 'Lemur Expiration Notification',
            'attachments': attachments,
            'channel': self.get_option('recipients', options),
            'username': self.get_option('username', options)
        }

        r = requests.post(self.get_option('webhook', options), json.dumps(body))
        if r.status_code not in [200]:
            raise Exception('Failed to send message')
        current_app.logger.error("Slack response: {0} Message Body: {1}".format(r.status_code, body))
