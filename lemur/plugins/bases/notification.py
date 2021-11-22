"""
.. module: lemur.plugins.bases.notification
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.common.utils import check_validation
from lemur.plugins.base import Plugin


class NotificationPlugin(Plugin):
    """
    This is the base class from which all of the supported
    issuers will inherit from.
    """

    type = "notification"

    def send(self, notification_type, message, targets, options, **kwargs):
        raise NotImplementedError

    def get_recipients(self, options, additional_recipients):
        """
        Given a set of options (which should include configured recipient info), returns the parsed list of recipients
        from those options plus the additional recipients specified. The returned value has no duplicates.

        For any notification types where recipients can't be dynamically modified, this returns only the additional recipients.
        """
        return additional_recipients


class ExpirationNotificationPlugin(NotificationPlugin):
    """
    This is the base class for all expiration notification plugins.
    It contains some default options that are needed for all expiration
    notification plugins.
    """

    default_options = [
        {
            "name": "interval",
            "type": "int",
            "required": True,
            "validation": check_validation(r"^\d+$"),
            "helpMessage": "Number of days to be alert before expiration.",
        },
        {
            "name": "unit",
            "type": "select",
            "required": True,
            "validation": check_validation(""),
            "available": ["days", "weeks", "months"],
            "helpMessage": "Interval unit",
        },
    ]

    @property
    def options(self):
        """
        Gets/sets options for the plugin.

        :return:
        """
        return self.default_options + self.additional_options

    def send(self, notification_type, message, excluded_targets, options, **kwargs):
        raise NotImplementedError
