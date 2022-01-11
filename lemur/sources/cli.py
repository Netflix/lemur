"""
.. module: lemur.sources.cli
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from copy import deepcopy
import sys
import time

from tabulate import tabulate
from flask_script import Manager
from flask import current_app
from sentry_sdk import capture_exception

from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS

from lemur.extensions import metrics
from lemur.plugins.base import plugins
from lemur.plugins.utils import get_plugin_option, set_plugin_option

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
@manager.option(
    "-ttl",
    "--time-to-live",
    type=int,
    dest="ttl",
    default=2,
    help="Time in hours, after which endpoint has not been refreshed, to remove endpoints from the source.",
)
def sync(source_strings, ttl):
    sources = validate_sources(source_strings)
    for source in sources:
        status = FAILURE_METRIC_STATUS

        start_time = time.time()
        print("[+] Staring to sync source: {label} and expire endpoints ttl={ttl}h\n".format(
            label=source.label, ttl=ttl))
        user = user_service.get_by_username("lemur")

        try:
            data = source_service.sync(source, user, ttl_hours=ttl)
            print(
                "[+] Certificates: New: {new} Updated: {updated}".format(
                    new=data["certificates"][0], updated=data["certificates"][1]
                )
            )
            print(
                "[+] Endpoints: New: {new} Updated: {updated} Expired: {expired}".format(
                    new=data["endpoints"][0], updated=data["endpoints"][1], expired=data["endpoints"][2]
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


@manager.option("-s", "--source", dest="source_label")
def enable_cloudfront(source_label):
    """
    Given the label of a legacy AWS source (without path or endpointType options), set up the source for CloudFront:

    #. Update the source options to the newest template, inheriting the existing values.
    #. Set ``path`` to "/" and ``endpointType`` to "elb" to restrict the source to discovering ELBs and related certs only.
    #. Create a new source (and destination) for the same accountNumber with ``path`` as "/cloudfront/" and ``endpointType`` as "cloudfront"

    :param source_strings:
    :return:
    """
    class ValidationError(Exception):
        pass
    try:
        source = source_service.get_by_label(source_label)
        if not source:
            raise ValidationError(f"Unable to find source with label: {source_label}")
        if source.plugin_name != "aws-source":
            raise ValidationError(f"Source '{source_label}' is not an AWS source")
        for opt_name in ["endpointType", "path"]:
            if get_plugin_option(opt_name, source.options) is not None:
                raise ValidationError(f"Source '{source_label}' already sets option '{opt_name}'")
        cloudfront_label = f"{source_label}-cloudfront"
        cloudfront_source = source_service.get_by_label(cloudfront_label)
        if cloudfront_source:
            raise ValidationError(f"A source named '{cloudfront_label}' already exists")

        p = plugins.get(source.plugin_name)
        new_options = deepcopy(p.options)
        for old_opt in source.options:
            name = old_opt["name"]
            value = get_plugin_option(name, source.options)
            set_plugin_option(name, value, new_options)
        set_plugin_option("path", "/", new_options)
        set_plugin_option("endpointType", "elb", new_options)
        source_service.update(source.id, source.label, source.plugin_name, new_options, source.description)

        cloudfront_options = deepcopy(new_options)
        set_plugin_option("path", "/cloudfront/", cloudfront_options)
        set_plugin_option("endpointType", "cloudfront", cloudfront_options)
        source_service.create(cloudfront_label, source.plugin_name, cloudfront_options,
                              f"CloudFront certificates and distributions for {source_label}")

        print(f"[+] Limited source {source_label} to discover ELBs and ELB certificates.\n")
        print(f"[+] Created source {cloudfront_label} to discover CloudFront distributions and certificates.\n")

    except ValidationError as e:
        print(f"[+] Error: {str(e)}")
        sys.exit(1)
