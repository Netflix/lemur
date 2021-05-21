"""
.. module: lemur.plugins.lemur_slack.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Harm Weites <harm@weites.com>
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json
import arrow
from flask import current_app
from lemur.common.utils import check_validation
from lemur.plugins.bases import ExpirationNotificationPlugin
from lemur.plugins import lemur_slack as slack

import requests


def create_certificate_url(name):
    return "https://{hostname}/#/certificates/{name}".format(
        hostname=current_app.config.get("LEMUR_HOSTNAME"), name=name
    )


def create_expiration_attachments(certificates):
    attachments = []
    for certificate in certificates:
        attachments.append(
            {
                "title": certificate["name"],
                "title_link": create_certificate_url(certificate["name"]),
                "color": "danger",
                "fallback": "",
                "fields": [
                    {"title": "Owner", "value": certificate["owner"], "short": True},
                    {
                        "title": "Expires",
                        "value": arrow.get(certificate["validityEnd"]).format(
                            "dddd, MMMM D, YYYY"
                        ),
                        "short": True,
                    },
                    {
                        "title": "Endpoints Detected",
                        "value": len(certificate["endpoints"]),
                        "short": True,
                    },
                ],
                "text": "",
                "mrkdwn_in": ["text"],
            }
        )
    return attachments


def create_rotation_attachments(certificate):
    return {
        "title": certificate["name"],
        "title_link": create_certificate_url(certificate["name"]),
        "fields": [
            {"title": "Owner", "value": certificate["owner"], "short": True},
            {
                "title": "Expires",
                "value": arrow.get(certificate["validityEnd"]).format(
                    "dddd, MMMM D, YYYY"
                ),
                "short": True,
            },
            {
                "title": "Endpoints Rotated",
                "value": len(certificate["endpoints"]),
                "short": True,
            },
        ],
    }


class SlackNotificationPlugin(ExpirationNotificationPlugin):
    title = "Slack"
    slug = "slack-notification"
    description = "Sends notifications to Slack"
    version = slack.VERSION

    author = "Harm Weites"
    author_url = "https://github.com/netflix/lemur"

    additional_options = [
        {
            "name": "webhook",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^https:\/\/hooks\.slack\.com\/services\/.+$"),
            "helpMessage": "The url Slack told you to use for this integration",
        },
        {
            "name": "username",
            "type": "str",
            "validation": check_validation("^.+$"),
            "helpMessage": "The great storyteller",
            "default": "Lemur",
        },
        {
            "name": "recipients",
            "type": "str",
            "required": True,
            "validation": check_validation("^(@|#).+$"),
            "helpMessage": "Where to send to, either @username or #channel",
        },
    ]

    def send(self, notification_type, message, targets, options, **kwargs):
        """
        A typical check can be performed using the notify command:
        `lemur notify`

        While we receive a `targets` parameter here, it is unused, as Slack webhooks do not allow
        dynamic re-targeting of messages. The webhook itself specifies a channel.
        """
        attachments = None
        if notification_type == "expiration":
            attachments = create_expiration_attachments(message)

        elif notification_type == "rotation":
            attachments = create_rotation_attachments(message)

        if not attachments:
            raise Exception("Unable to create message attachments")

        body = {
            "text": f"Lemur {notification_type.capitalize()} Notification",
            "attachments": attachments,
            "channel": self.get_option("recipients", options),
            "username": self.get_option("username", options),
        }

        r = requests.post(self.get_option("webhook", options), json.dumps(body))

        if r.status_code not in [200]:
            raise Exception(f"Failed to send message. Slack response: {r.status_code} {body}")

        current_app.logger.info(
            f"Slack response: {r.status_code} Message Body: {body}"
        )
