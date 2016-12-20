"""
.. module: lemur.sources.cli
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
import time

from tabulate import tabulate

from flask_script import Manager

from flask import current_app

from lemur.extensions import metrics
from lemur.sources import service as source_service
from lemur.users import service as user_service

manager = Manager(usage="Handles all source related tasks.")


def validate_sources(source_strings):
    sources = []
    if not source_strings:
        table = []
        for source in source_service.get_all():
            table.append([source.label, source.active, source.description])

        print("No source specified choose from below:")
        print(tabulate(table, headers=['Label', 'Active', 'Description']))
        sys.exit(1)

    if 'all' in source_strings:
        sources = source_service.get_all()
    else:
        for source_str in source_strings:
            source = source_service.get_by_label(source_str)

            if not source:
                print("Unable to find specified source with label: {0}".format(source_str))
                sys.exit(1)

            sources.append(source)
    return sources


@manager.option('-s', '--sources', dest='source_strings', action='append', help='Sources to operate on.')
def sync(source_strings):
    source_objs = validate_sources(source_strings)
    for source in source_objs:
        start_time = time.time()
        print("[+] Staring to sync source: {label}!\n".format(label=source.label))

        user = user_service.get_by_username('lemur')

        try:
            data = source_service.sync(source, user)
            print(
                "[+] Certificates: New: {new} Updated: {updated}".format(
                    new=data['certificates'][0],
                    updated=data['certificates'][1]
                )
            )
            print(
                "[+] Endpoints: New: {new} Updated: {updated}".format(
                    new=data['endpoints'][0],
                    updated=data['endpoints'][1]
                )
            )
            print(
                "[+] Finished syncing source: {label}. Run Time: {time}".format(
                    label=source.label,
                    time=(time.time() - start_time)
                )
            )
        except Exception as e:
            current_app.logger.exception(e)

            print(
                "[X] Failed syncing source {label}!\n".format(label=source.label)
            )

            metrics.send('sync_failed', 'counter', 1, metric_tags={'source': source.label})


@manager.option('-s', '--sources', dest='source_strings', action='append', help='Sources to operate on.')
def clean(source_strings):
    source_objs = validate_sources(source_strings)
    for source in source_objs:
        start_time = time.time()
        print("[+] Staring to clean source: {label}!\n".format(label=source.label))
        source_service.clean(source)
        print(
            "[+] Finished cleaning source: {label}. Run Time: {time}\n".format(
                label=source.label,
                time=(time.time() - start_time)
            )
        )
