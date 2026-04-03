"""
.. module: lemur.plugins.lemur_telegram.plugin
    :platform: Unix
    :copyright: (c) 2025 by Fedor S
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Fedor S <fedorwww@gmail.com>
"""
import arrow
import requests
from flask import current_app

from lemur.common.utils import check_validation
from lemur.plugins import lemur_telegram as telegram
from lemur.plugins.bases import ExpirationNotificationPlugin


def escape(text):
    special = r'_*[]()~`>#+-=|{}.!'
    return ''.join('\\' + c if c in special else c for c in text)


def create_certificate_url(name):
    return "https://{hostname}/#/certificates/{name}".format(
        hostname=current_app.config.get("LEMUR_HOSTNAME"), name=name
    )


def create_expiration_attachments(certificates):
    attachments = []
    for certificate in certificates:
        name = escape(certificate["name"])
        owner = escape(certificate["owner"])
        url = create_certificate_url(certificate["name"])
        expires = arrow.get(certificate["validityEnd"]).format("dddd, MMMM D, YYYY")
        endpoints = len(certificate["endpoints"])
        attachments.append(
            f"*Certificate:* [{name}]({url})\n*Owner:* {owner}\n*Expires:* {expires}\n*Endpoints:* {endpoints}\n\n"
        )
    return attachments


def create_rotation_attachments(certificate):
    name = escape(certificate["name"])
    owner = escape(certificate["owner"])
    url = create_certificate_url(certificate["name"])
    expires = arrow.get(certificate["validityEnd"]).format("dddd, MMMM D, YYYY")
    endpoints = len(certificate["endpoints"])
    return f"*Certificate:* [{name}]({url})\n*Owner:* {owner}\n*Expires:* {expires}\n*Endpoints rotated:* {endpoints}\n\n"


class TelegramNotificationPlugin(ExpirationNotificationPlugin):
    title = "Telegram"
    slug = "tg-notification"
    description = "Sends certificate expiration notifications to Telegram"
    version = telegram.VERSION

    author = "Fedor S"
    author_url = "https://github.com/netflix/lemur"

    additional_options = [
        {
            "name": "chat",
            "type": "str",
            "required": True,
            "validation": check_validation("^[+-]?\d+(\.\d+)?$"),
            "helpMessage": "The chat id to send notification to",
        },
        {
            "name": "token",
            "type": "str",
            "required": True,
            "validation": check_validation("^\d+:[A-Za-z0-9_]+$"),
            "helpMessage": "Bot API Token",
        },
    ]

    def send(self, notification_type, message, targets, options, **kwargs):
        """
        A typical check can be performed using the notify command:
        `lemur notify`

        While we receive a `targets` parameter here, it is unused, plugin currently supports sending to only one chat.
        """
        attachments = None
        if notification_type == "expiration":
            attachments = create_expiration_attachments(message)

        elif notification_type == "rotation":
            attachments = create_rotation_attachments(message)

        if not attachments:
            raise Exception("Unable to create message attachments")

        data = {
            "parse_mode": "MarkdownV2",
            "chat_id": self.get_option("chat", options),
            "text": "*Lemur {} Notification*\n\n{}".format(notification_type.capitalize(), *attachments),
        }

        r = requests.post("https://api.telegram.org/bot{}/sendMessage".format(self.get_option("token", options)),
                          data=data)

        if r.status_code not in [200]:
            raise Exception(f"Failed to send message. Telegram response: {r.status_code} {data}")

        current_app.logger.info(
            f"Telegram response: {r.status_code} Message Body: {data}"
        )
