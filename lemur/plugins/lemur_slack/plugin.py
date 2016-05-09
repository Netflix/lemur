"""
.. module: lemur.plugins.lemur_slack.slack
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Harm Weites <harm@weites.com>
"""
from flask import current_app
from lemur.plugins.bases import ExpirationNotificationPlugin
from lemur.plugins import lemur_slack as slack

import requests


def find_value(name, options):
    for o in options:
        if o['name'] == name:
            return o['value']


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
            'required': True,
            'validation': '^.+$',
            'helpMessage': 'The great storyteller',
        }, {
            'name': 'recipients',
            'type': 'str',
            'required': True,
            'validation': '^(@|#).+$',
            'helpMessage': 'Where to send to, either @username or #channel',
        },
    ]

    @staticmethod
    def send(event_type, message, targets, options, **kwargs):
        """
        A typical check can be performed using the notify command:
        `lemur notify`
        """
        msg = 'Certificate expiry pending for certificate:\n*%s*\nCurrent state is: _%s_' % (message[0]['name'], event_type)
        body = '{"text": "%s", "channel": "%s", "username": "%s"}' % (msg, find_value('recipients', options), find_value('username', options))

        current_app.logger.info("Sending message to Slack: %s" % body)
        current_app.logger.debug("Sending data to Slack endpoint at %s" % find_value('webhook', options))

        r = requests.post(find_value('webhook', options), body)
        if r.status_code not in [200]:
            current_app.logger.error("Slack response: %s" % r.status_code)
            raise
