"""
.. module: lemur.sources.service
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow

from flask import current_app

from lemur import database
from lemur.sources.models import Source
from lemur.certificates.models import Certificate
from lemur.certificates import service as certificate_service
from lemur.endpoints import service as endpoint_service
from lemur.destinations import service as destination_service

from lemur.certificates.schemas import CertificateUploadInputSchema

from lemur.plugins.base import plugins


def certificate_create(certificate, source):
    data, errors = CertificateUploadInputSchema().load(certificate)

    if errors:
        raise Exception("Unable to import certificate: {reasons}".format(reasons=errors))

    data['creator'] = certificate['creator']

    cert = certificate_service.import_certificate(**data)
    cert.description = "This certificate was automatically discovered by Lemur"
    cert.sources.append(source)
    sync_update_destination(cert, source)
    database.update(cert)
    return cert


def certificate_update(certificate, source):
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


def sync_endpoints(source):
    new, updated = 0, 0
    current_app.logger.debug("Retrieving endpoints from {0}".format(source.label))
    s = plugins.get(source.plugin_name)

    try:
        endpoints = s.get_endpoints(source.options)
    except NotImplementedError:
        current_app.logger.warning("Unable to sync endpoints for source {0} plugin has not implemented 'get_endpoints'".format(source.label))
        return

    for endpoint in endpoints:
        exists = endpoint_service.get_by_dnsname(endpoint['dnsname'])

        certificate_name = endpoint.pop('certificate_name')

        endpoint['certificate'] = certificate_service.get_by_name(certificate_name)

        if not endpoint['certificate']:
            current_app.logger.error(
                "Certificate Not Found. Name: {0} Endpoint: {1}".format(certificate_name, endpoint['name']))
            continue

        policy = endpoint.pop('policy')

        policy_ciphers = []
        for nc in policy['ciphers']:
            policy_ciphers.append(endpoint_service.get_or_create_cipher(name=nc))

        policy['ciphers'] = policy_ciphers
        endpoint['policy'] = endpoint_service.get_or_create_policy(**policy)
        endpoint['source'] = source

        if not exists:
            current_app.logger.debug("Endpoint Created: Name: {name}".format(name=endpoint['name']))
            endpoint_service.create(**endpoint)
            new += 1

        else:
            current_app.logger.debug("Endpoint Updated: Name: {name}".format(name=endpoint['name']))
            endpoint_service.update(exists.id, **endpoint)
            updated += 1

    return new, updated


def sync_certificates(source, user):
    new, updated = 0, 0

    current_app.logger.debug("Retrieving certificates from {0}".format(source.label))
    s = plugins.get(source.plugin_name)
    certificates = s.get_certificates(source.options)

    for certificate in certificates:
        exists = certificate_service.get_by_name(certificate['name'])

        certificate['owner'] = user.email
        certificate['creator'] = user

        if not exists:
            current_app.logger.debug("Creating Certificate. Name: {name}".format(name=certificate['name']))
            certificate_create(certificate, source)
            new += 1

        else:
            current_app.logger.debug("Updating Certificate. Name: {name}".format(name=certificate['name']))
            certificate_update(exists, source)
            updated += 1

    assert len(certificates) == new + updated

    return new, updated


def sync(source, user):
    new_certs, updated_certs = sync_certificates(source, user)
    new_endpoints, updated_endpoints = sync_endpoints(source)

    source.last_run = arrow.utcnow()
    database.update(source)

    return {'endpoints': (new_endpoints, updated_endpoints), 'certificates': (new_certs, updated_certs)}


def create(label, plugin_name, options, description=None):
    """
    Creates a new source, that can then be used as a source for certificates.

    :param label: Source common name
    :param plugin_name:
    :param options:
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
    :param options:
    :param description:
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
    Retrieves an source by its lemur assigned ID.

    :param source_id: Lemur assigned ID
    :rtype : Source
    :return:
    """
    return database.get(Source, source_id)


def get_by_label(label):
    """
    Retrieves a source by its label

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

    return database.sort_and_page(query, Source, args)
