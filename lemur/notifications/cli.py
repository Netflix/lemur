"""
.. module: lemur.notifications.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask_script import Manager

from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.extensions import sentry, metrics
from lemur.notifications.messaging import send_expiration_notifications

manager = Manager(usage="Handles notification related tasks.")


@manager.option(
    "-e",
    "--exclude",
    dest="exclude",
    action="append",
    default=[],
    help="Common name matching of certificates that should be excluded from notification",
)
def expirations(exclude):
    """
    Runs Lemur's notification engine, that looks for expired certificates and sends
    notifications out to those that have subscribed to them.

    Every certificate receives notifications by default. When expiration notifications are handled outside of Lemur
    we exclude their names (or matching) from expiration notifications.

    It performs simple subset matching and is case insensitive.

    :return:
    """
    status = FAILURE_METRIC_STATUS
    try:
        print("Starting to notify subscribers about expiring certificates!")
        success, failed = send_expiration_notifications(exclude)
        print(
            "Finished notifying subscribers about expiring certificates! Sent: {success} Failed: {failed}".format(
                success=success, failed=failed
            )
        )
        status = SUCCESS_METRIC_STATUS
    except Exception as e:
        sentry.captureException()

    metrics.send(
        "expiration_notification_job", "counter", 1, metric_tags={"status": status}
    )
