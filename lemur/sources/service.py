"""
.. module: lemur.sources.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app

from lemur import database
from lemur.sources.models import Source
from lemur.certificates.models import Certificate
from lemur.certificates import service as cert_service
from lemur.destinations import service as destination_service

from lemur.plugins.base import plugins


def _disassociate_certs_from_source(current_certificates, found_certificates, source_label):
    missing = []
    for cc in current_certificates:
        for fc in found_certificates:
            if fc['public_certificate'] == cc.body:
                break
        else:
            missing.append(cc)

    for c in missing:
        for s in c.sources:
            if s.label == source_label:
                current_app.logger.info(
                    "Certificate {name} is no longer associated with {source}".format(
                        name=c.name,
                        source=source_label
                    )
                )
                c.sources.delete(s)


def sync_create(certificate, source):
    cert = cert_service.import_certificate(**certificate)
    cert.description = "This certificate was automatically discovered by Lemur"
    cert.sources.append(source)
    sync_update_destination(cert, source)
    database.update(cert)


def sync_update(certificate, source):
    for s in certificate.sources:
        if s.label == source.label:
            break
    else:
        certificate.sources.append(source)

    sync_update_destination(certificate, source)
    database.update(certificate)


def sync_update_destination(certificate, source):
    dest = destination_service.get_by_label(source.label)
    if dest:
        for d in certificate.destinations:
            if d.label == source.label:
                break
        else:
            certificate.destinations.append(dest)


def sync(labels=None):
    new, updated = 0, 0
    c_certificates = cert_service.get_all_certs()

    for source in database.get_all(Source, True, field='active'):
        # we should be able to specify, individual sources to sync
        if labels:
            if source.label not in labels:
                continue

        current_app.logger.error("Retrieving certificates from {0}".format(source.label))
        s = plugins.get(source.plugin_name)
        certificates = s.get_certificates(source.options)

        for certificate in certificates:
            exists = cert_service.find_duplicates(certificate['public_certificate'])

            if not exists:
                sync_create(certificate, source)
                new += 1

            # check to make sure that existing certificates have the current source associated with it
            elif len(exists) == 1:
                sync_update(exists[0], source)
                updated += 1
            else:
                current_app.logger.warning(
                    "Multiple certificates found, attempt to deduplicate the following certificates: {0}".format(
                        ",".join([x.name for x in exists])
                    )
                )

        # we need to try and find the absent of certificates so we can properly disassociate them when they are deleted
        _disassociate_certs_from_source(c_certificates, certificates, source)


def create(label, plugin_name, options, description=None):
    """
    Creates a new source, that can then be used as a source for certificates.

    :param label: Source common name
    :param description:
    :rtype : Source
    :return: New source
    """
    source = Source(label=label, options=options, plugin_name=plugin_name, description=description)
    return database.create(source)


def update(source_id, label, options, description):
    """
    Updates an existing source.

    :param source_id:  Lemur assigned ID
    :param label: Source common name
    :rtype : Source
    :return:
    """
    source = get(source_id)

    source.label = label
    source.options = options
    source.description = description

    return database.update(source)


def delete(source_id):
    """
    Deletes an source.

    :param source_id: Lemur assigned ID
    """
    database.delete(get(source_id))


def get(source_id):
    """
    Retrieves an source by it's lemur assigned ID.

    :param source_id: Lemur assigned ID
    :rtype : Source
    :return:
    """
    return database.get(Source, source_id)


def get_by_label(label):
    """
    Retrieves a source by it's label

    :param label:
    :return:
    """
    return database.get(Source, label, field='label')


def get_all():
    """
    Retrieves all source currently known by Lemur.

    :return:
    """
    query = database.session_query(Source)
    return database.find_all(query, Source, {}).all()


def render(args):
    sort_by = args.pop('sort_by')
    sort_dir = args.pop('sort_dir')
    page = args.pop('page')
    count = args.pop('count')
    filt = args.pop('filter')
    certificate_id = args.pop('certificate_id', None)

    if certificate_id:
        query = database.session_query(Source).join(Certificate, Source.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Source)

    if filt:
        terms = filt.split(';')
        query = database.filter(query, Source, terms)

    query = database.find_all(query, Source, args)

    if sort_by and sort_dir:
        query = database.sort(query, Source, sort_by, sort_dir)

    return database.paginate(query, page, count)
