"""
.. module: lemur.notifications.cli
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask_script import Manager

from lemur.notifications.messaging import send_expiration_notifications

manager = Manager(usage="Handles notification related tasks.")


@manager.command
def expirations():
    """
    Runs Lemur's notification engine, that looks for expired certificates and sends
    notifications out to those that have subscribed to them.

    :return:
    """
    print("Starting to notify subscribers about expiring certificates!")
    count = send_expiration_notifications()
    print(
        "Finished notifying subscribers about expiring certificates! Sent {count} notifications!".format(
            count=count
        )
    )
