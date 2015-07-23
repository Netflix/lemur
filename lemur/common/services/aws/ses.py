"""
.. module: lemur.common.services.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import boto.ses
from flask import current_app

from lemur.templates.config import env


def send(subject, data, email_type, recipients):
    """
    Configures all Lemur email messaging

    :param subject:
    :param data:
    :param email_type:
    :param recipients:
    """
    conn = boto.connect_ses()
    # jinja template depending on type
    template = env.get_template('{}.html'.format(email_type))
    body = template.render(**data)
    conn.send_email(current_app.config.get("LEMUR_EMAIL"), subject, body, recipients, format='html')
