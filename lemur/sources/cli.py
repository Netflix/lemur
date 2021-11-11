"""
.. module: lemur.sources.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
import time

from tabulate import tabulate
from flask_script import Manager
from flask import current_app
from sentry_sdk import capture_exception

from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS

from lemur.extensions import metrics
from lemur.plugins.base import plugins

from lemur.destinations import service as dest_service
from lemur.sources import service as source_service
from lemur.users import service as user_service
from lemur.certificates import service as certificate_service


manager = Manager(usage="Handles all source related tasks.")


def validate_sources(source_strings):
    sources = []
    if not source_strings:
        table = []
        for source in source_service.get_all():
            table.append([source.label, source.active, source.description])

        print("No source specified choose from below:")
        print(tabulate(table, headers=["Label", "Active", "Description"]))
        sys.exit(1)

    if "all" in source_strings:
        sources = source_service.get_all()
    else:
        for source_str in source_strings:
            source = source_service.get_by_label(source_str)

            if not source:
                print(
                    "Unable to find specified source with label: {0}".format(source_str)
                )
                sys.exit(1)

            sources.append(source)
    return sources


def validate_destinations(destination_strings):
    if not destination_strings:
        table = []
        for dest in dest_service.get_all():
            table.append([dest.label, dest.description])

        print("No destination specified choose from below:")
        print(tabulate(table, headers=["Label", "Description"]))
        sys.exit(1)

    if "all" in destination_strings:
        return dest_service.get_all()

    destinations = []
    for label in destination_strings:
        dest = dest_service.get_by_label(label)

        if not dest:
            print(
                "Unable to find specified destination with label: {0}".format(label)
            )
            sys.exit(1)

        destinations.append(dest)
    return destinations


def execute_clean(plugin, certificate, source):
    try:
        plugin.clean(certificate, source.options)
        certificate.sources.remove(source)

        # If we want to remove the source from the certificate, we also need to clear any equivalent destinations to
        # prevent Lemur from re-uploading the certificate.
        for destination in certificate.destinations:
            if destination.label == source.label:
                certificate.destinations.remove(destination)

        certificate_service.database.update(certificate)
        return SUCCESS_METRIC_STATUS
    except Exception as e:
        current_app.logger.exception(e)
        capture_exception()


@manager.option(
    "-s",
    "--sources",
    dest="source_strings",
    action="append",
    help="Sources to operate on.",
)
def sync(source_strings):
    sources = validate_sources(source_strings)
    for source in sources:
        status = FAILURE_METRIC_STATUS

        start_time = time.time()
        print("[+] Staring to sync source: {label}!\n".format(label=source.label))

        user = user_service.get_by_username("lemur")

        try:
            data = source_service.sync(source, user)
            print(
                "[+] Certificates: New: {new} Updated: {updated}".format(
                    new=data["certificates"][0], updated=data["certificates"][1]
                )
            )
            print(
                "[+] Endpoints: New: {new} Updated: {updated}".format(
                    new=data["endpoints"][0], updated=data["endpoints"][1]
                )
            )
            print(
                "[+] Finished syncing source: {label}. Run Time: {time}".format(
                    label=source.label, time=(time.time() - start_time)
                )
            )
            status = SUCCESS_METRIC_STATUS

        except Exception as e:
            current_app.logger.exception(e)

            print("[X] Failed syncing source {label}!\n".format(label=source.label))

            capture_exception()
            metrics.send(
                "source_sync_fail",
                "counter",
                1,
                metric_tags={"source": source.label, "status": status},
            )

        metrics.send(
            "source_sync",
            "counter",
            1,
            metric_tags={"source": source.label, "status": status},
        )


@manager.option(
    "-s",
    "--sources",
    dest="source_strings",
    action="append",
    help="Sources to operate on.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def clean(source_strings, commit):
    sources = validate_sources(source_strings)
    for source in sources:
        s = plugins.get(source.plugin_name)

        if not hasattr(s, "clean"):
            info_text = f"Cannot clean source: {source.label}, source plugin does not implement 'clean()'"
            current_app.logger.warning(info_text)
            print(info_text)
            continue

        start_time = time.time()

        print("[+] Staring to clean source: {label}!\n".format(label=source.label))

        cleaned = 0
        certificates = certificate_service.get_all_pending_cleaning_expired(source)
        for certificate in certificates:
            status = FAILURE_METRIC_STATUS
            if commit:
                status = execute_clean(s, certificate, source)

            metrics.send(
                "certificate_clean",
                "counter",
                1,
                metric_tags={"status": status, "source": source.label, "certificate": certificate.name},
            )
            current_app.logger.warning(f"Removed {certificate.name} from source {source.label} during cleaning")
            cleaned += 1

        info_text = f"[+] Finished cleaning source: {source.label}. " \
                    f"Removed {cleaned} certificates from source. " \
                    f"Run Time: {(time.time() - start_time)}\n"
        print(info_text)
        current_app.logger.warning(info_text)


@manager.option(
    "-s",
    "--sources",
    dest="source_strings",
    action="append",
    help="Sources to operate on.",
)
@manager.option(
    "-d",
    "--days",
    dest="days_to_expire",
    type=int,
    action="store",
    required=True,
    help="The expiry range within days.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def clean_unused_and_expiring_within_days(source_strings, days_to_expire, commit):
    sources = validate_sources(source_strings)
    for source in sources:
        s = plugins.get(source.plugin_name)

        if not hasattr(s, "clean"):
            info_text = f"Cannot clean source: {source.label}, source plugin does not implement 'clean()'"
            current_app.logger.warning(info_text)
            print(info_text)
            continue

        start_time = time.time()

        print("[+] Staring to clean source: {label}!\n".format(label=source.label))

        cleaned = 0
        certificates = certificate_service.get_all_pending_cleaning_expiring_in_days(source, days_to_expire)
        for certificate in certificates:
            status = FAILURE_METRIC_STATUS
            if commit:
                status = execute_clean(s, certificate, source)

            metrics.send(
                "certificate_clean",
                "counter",
                1,
                metric_tags={"status": status, "source": source.label, "certificate": certificate.name},
            )
            current_app.logger.warning(f"Removed {certificate.name} from source {source.label} during cleaning")
            cleaned += 1

        info_text = f"[+] Finished cleaning source: {source.label}. " \
                    f"Removed {cleaned} certificates from source. " \
                    f"Run Time: {(time.time() - start_time)}\n"
        print(info_text)
        current_app.logger.warning(info_text)


@manager.option(
    "-s",
    "--sources",
    dest="source_strings",
    action="append",
    help="Sources to operate on.",
)
@manager.option(
    "-d",
    "--days",
    dest="days_since_issuance",
    type=int,
    action="store",
    required=True,
    help="Days since issuance.",
)
@manager.option(
    "-c",
    "--commit",
    dest="commit",
    action="store_true",
    default=False,
    help="Persist changes.",
)
def clean_unused_and_issued_since_days(source_strings, days_since_issuance, commit):
    sources = validate_sources(source_strings)
    for source in sources:
        s = plugins.get(source.plugin_name)

        if not hasattr(s, "clean"):
            info_text = f"Cannot clean source: {source.label}, source plugin does not implement 'clean()'"
            current_app.logger.warning(info_text)
            print(info_text)
            continue

        start_time = time.time()

        print("[+] Staring to clean source: {label}!\n".format(label=source.label))

        cleaned = 0
        certificates = certificate_service.get_all_pending_cleaning_issued_since_days(source, days_since_issuance)
        for certificate in certificates:
            status = FAILURE_METRIC_STATUS
            if commit:
                status = execute_clean(s, certificate, source)

            metrics.send(
                "certificate_clean",
                "counter",
                1,
                metric_tags={"status": status, "source": source.label, "certificate": certificate.name},
            )
            current_app.logger.warning(f"Removed {certificate.name} from source {source.label} during cleaning")
            cleaned += 1

        info_text = f"[+] Finished cleaning source: {source.label}. " \
                    f"Removed {cleaned} certificates from source. " \
                    f"Run Time: {(time.time() - start_time)}\n"
        print(info_text)
        current_app.logger.warning(info_text)


@manager.option(
    "-d",
    "--destinations",
    dest="labels",
    action="append",
    help="Destinations to operate on.",
)
def sync_source_destination(labels):
    """
    This command will sync destination and source, to make sure eligible destinations are also present as source.
    Destination eligibility is determined on the sync_as_source attribute of the plugin.
    The destination sync_as_source_name provides the name of the suitable source-plugin.
    We use (account number, IAM path) tuple uniqueness to avoid duplicate sources.

    Lemur now does this automatically during destination create and update, so this command is primarily useful
    for migrating legacy destinations.  Set "-d all" to sync all destinations.
    """
    destinations = validate_destinations(labels)
    for destination in destinations:
        if source_service.add_aws_destination_to_sources(destination):
            info_text = f"[+] New source added: {destination.label}.\n"
            print(info_text)
            current_app.logger.warning(info_text)
