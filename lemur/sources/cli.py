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
from lemur.plugins.base import plugins

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
    sources = validate_sources(source_strings)
    for source in sources:
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
@manager.option('-c', '--commit', dest='commit', action='store_true', default=False, help='Persist changes.')
def clean(source_strings, commit):
    sources = validate_sources(source_strings)
    for source in sources:
        s = plugins.get(source.plugin_name)

        if not hasattr(s, 'clean'):
            print("Cannot clean source: {0}, source plugin does not implement 'clean()'".format(
                source.label
            ))
            continue

        start_time = time.time()

        print("[+] Staring to clean source: {label}!\n".format(label=source.label))

        cleaned = 0
        for certificate in certificate_service.get_all_pending_cleaning(source):
                if commit:
                    try:
                        s.clean(certificate, source.options)
                        certificate.sources.remove(source)
                        certificate_service.database.update(certificate)
                        metrics.send('clean_success', 'counter', 1, metric_tags={'source': source.label})
                    except Exception as e:
                        current_app.logger.exception(e)
                        metrics.send('clean_failed', 'counter', 1, metric_tags={'source': source.label})

                current_app.logger.warning("Removed {0} from source {1} during cleaning".format(
                    certificate.name,
                    source.label
                ))

                cleaned += 1

        print(
            "[+] Finished cleaning source: {label}. Removed {cleaned} certificates from source. Run Time: {time}\n".format(
                label=source.label,
                time=(time.time() - start_time),
                cleaned=cleaned
            )
        )
