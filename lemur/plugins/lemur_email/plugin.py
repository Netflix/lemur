"""
.. module: lemur.plugins.lemur_email.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import boto3
from html.parser import HTMLParser
from flask import current_app
from flask_mail import Message
from sentry_sdk import capture_exception

from lemur.constants import EMAIL_RE, EMAIL_RE_HELP
from lemur.extensions import smtp_mail
from lemur.exceptions import InvalidConfiguration

from lemur.plugins.bases import ExpirationNotificationPlugin
from lemur.plugins import lemur_email as email

from lemur.plugins.lemur_email.templates.config import env
from lemur.plugins.utils import get_plugin_option


def render_html(template_name, options, certificates):
    """
    Renders the html for our email notification.

    :param template_name:
    :param options:
    :param certificates:
    :return:
    """
    message = {"options": options, "certificates": certificates}
    template = env.get_template(f"{template_name}.html")
    return template.render(
        dict(message=message, hostname=current_app.config.get("LEMUR_HOSTNAME"))
    )


def send_via_smtp(subject, body, targets):
    """
    Attempts to deliver email notification via SMTP.

    :param subject:
    :param body:
    :param targets:
    :return:
    """
    msg = Message(
        subject, recipients=targets, sender=current_app.config.get("LEMUR_EMAIL")
    )
    msg.body = ""  # kinda a weird api for sending html emails
    msg.html = body
    smtp_mail.send(msg)


def send_via_ses(subject, body, targets, **kwargs):
    """
    Attempts to deliver email notification via SES service.
    :param subject:
    :param body:
    :param targets:
    :return:
    """
    email_tags = kwargs.get("email_tags")
    if not email_tags:
        email_tags = {}
    email_tags["subject"] = subject
    email_tags["targets"] = targets

    ses_region = current_app.config.get("LEMUR_SES_REGION", "us-east-1")
    client = boto3.client("ses", region_name=ses_region)
    source_arn = current_app.config.get("LEMUR_SES_SOURCE_ARN")
    args = {
        "Source": current_app.config.get("LEMUR_EMAIL"),
        "Destination": {"ToAddresses": targets},
        "Message": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Html": {"Data": body, "Charset": "UTF-8"}},
        },
    }
    if source_arn:
        args["SourceArn"] = source_arn
    response = client.send_email(**args)
    try:
        # logging information about the email (particularly the message ID) allows reconcilitation with SES bounce notifications
        message_id = response["MessageId"]
        email_tags["ses_message_id"] = message_id
        current_app.logger.info(f"Sent SES email: {message_id}", extra={"SES-Email": email_tags})
    except Exception:
        current_app.logger.error("Unable to log message ID of sent SES email", extra={"SES-Email": email_tags},
                                 exc_info=True)
        capture_exception()


class TitleParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.match = False
        self.title = ''

    def handle_starttag(self, tag, attributes):
        self.match = tag == 'title'

    def handle_data(self, data):
        if self.match:
            self.title = data
            self.match = False


class EmailNotificationPlugin(ExpirationNotificationPlugin):
    title = "Email"
    slug = "email-notification"
    description = "Sends expiration email notifications"
    version = email.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur"

    additional_options = [
        {
            "name": "recipients",
            "type": "str",
            "required": True,
            "validation": EMAIL_RE.pattern,
            "helpMessage": EMAIL_RE_HELP,
        }
    ]

    def __init__(self, *args, **kwargs):
        """Initialize the plugin with the appropriate details."""
        sender = current_app.config.get("LEMUR_EMAIL_SENDER", "ses").lower()

        if sender not in ["ses", "smtp"]:
            raise InvalidConfiguration("Email sender type {0} is not recognized.")

    @staticmethod
    def send(notification_type, message, targets, options, **kwargs):
        if not targets:
            return

        readable_notification_type = ' '.join(map(lambda x: x.capitalize(), notification_type.split('_')))
        subject = f"Lemur: {readable_notification_type} Notification"

        body = render_html(notification_type, options, message)
        title_parser = TitleParser()
        title_parser.feed(body)
        if title_parser.title:
            subject = title_parser.title

        s_type = current_app.config.get("LEMUR_EMAIL_SENDER", "ses").lower()

        if s_type == "ses":
            send_via_ses(subject, body, targets, **kwargs)

        elif s_type == "smtp":
            send_via_smtp(subject, body, targets)

    @staticmethod
    def get_recipients(options, additional_recipients, **kwargs):
        notification_recipients = get_plugin_option("recipients", options)
        if notification_recipients:
            notification_recipients = notification_recipients.split(",")

        return list(set(notification_recipients + additional_recipients))
