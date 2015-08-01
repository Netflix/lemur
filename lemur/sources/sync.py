"""
.. module: lemur.sources.sync
    :platform: Unix
    :synopsis: This module contains various certificate syncing operations.
    Because of the nature of the SSL environment there are multiple ways
    a certificate could be created without Lemur's knowledge. Lemur attempts
    to 'sync' with as many different datasources as possible to try and track
    any certificate that may be in use.

    These operations are typically run on a periodic basis from either the command
    line or a cron job.

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from lemur.certificates import service as cert_service

from lemur.plugins.base import plugins
from lemur.plugins.bases.source import SourcePlugin


def sync():
    for plugin in plugins:
        new = 0
        updated = 0
        if isinstance(plugin, SourcePlugin):
            if plugin.is_enabled():
                current_app.logger.error("Retrieving certificates from {0}".format(plugin.title))
                certificates = plugin.get_certificates()

                for certificate in certificates:
                    exists = cert_service.find_duplicates(certificate)

                    if not exists:
                        cert_service.import_certificate(**certificate)
                        new += 1

                    if len(exists) == 1:
                        updated += 1

                # TODO associated cert with source
                # TODO update cert if found from different source
                # TODO disassociate source if missing
