"""
.. module: lemur.sources.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
import copy

from flask import current_app

from lemur import database
from lemur.sources.models import Source
from lemur.certificates.models import Certificate
from lemur.certificates import service as certificate_service
from lemur.endpoints import service as endpoint_service
from lemur.extensions import metrics
from lemur.destinations import service as destination_service

from lemur.certificates.schemas import CertificateUploadInputSchema
from lemur.common.utils import find_matching_certificates_by_hash, parse_certificate
from lemur.common.defaults import serial

from lemur.plugins.base import plugins
from lemur.plugins.utils import get_plugin_option, set_plugin_option


def certificate_create(certificate, source):
    data, errors = CertificateUploadInputSchema().load(certificate)

    if errors:
        raise Exception(
            "Unable to import certificate: {reasons}".format(reasons=errors)
        )

    data["creator"] = certificate["creator"]

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
        current_app.logger.warning(
            "Unable to sync endpoints for source {0} plugin has not implemented 'get_endpoints'".format(
                source.label
            )
        )
        return new, updated

    for endpoint in endpoints:
        exists = endpoint_service.get_by_dnsname_and_port(
            endpoint["dnsname"], endpoint["port"]
        )

        certificate_name = endpoint.pop("certificate_name")

        endpoint["certificate"] = certificate_service.get_by_name(certificate_name)

        if not endpoint["certificate"]:
            current_app.logger.error(
                "Certificate Not Found. Name: {0} Endpoint: {1}".format(
                    certificate_name, endpoint["name"]
                )
            )
            metrics.send("endpoint.certificate.not.found",
                         "counter", 1,
                         metric_tags={"cert": certificate_name, "endpoint": endpoint["name"], "acct": s.get_option("accountNumber", source.options)})
            continue

        policy = endpoint.pop("policy")

        policy_ciphers = []
        for nc in policy["ciphers"]:
            policy_ciphers.append(endpoint_service.get_or_create_cipher(name=nc))

        policy["ciphers"] = policy_ciphers
        endpoint["policy"] = endpoint_service.get_or_create_policy(**policy)
        endpoint["source"] = source

        if not exists:
            current_app.logger.debug(
                "Endpoint Created: Name: {name}".format(name=endpoint["name"])
            )
            endpoint_service.create(**endpoint)
            new += 1

        else:
            current_app.logger.debug("Endpoint Updated: {}".format(endpoint))
            endpoint_service.update(exists.id, **endpoint)
            updated += 1

    return new, updated


# TODO this is very slow as we don't batch update certificates
def sync_certificates(source, user):
    new, updated = 0, 0

    current_app.logger.debug("Retrieving certificates from {0}".format(source.label))
    s = plugins.get(source.plugin_name)
    certificates = s.get_certificates(source.options)

    for certificate in certificates:
        exists = False

        if certificate.get("search", None):
            conditions = certificate.pop("search")
            exists = certificate_service.get_by_attributes(conditions)

        if not exists and certificate.get("name"):
            result = certificate_service.get_by_name(certificate["name"])
            if result:
                exists = [result]

        if not exists and certificate.get("serial"):
            exists = certificate_service.get_by_serial(certificate["serial"])

        if not exists:
            cert = parse_certificate(certificate["body"])
            matching_serials = certificate_service.get_by_serial(serial(cert))
            exists = find_matching_certificates_by_hash(cert, matching_serials)

        if not certificate.get("owner"):
            certificate["owner"] = user.email

        certificate["creator"] = user
        exists = [x for x in exists if x]

        if not exists:
            certificate_create(certificate, source)
            new += 1

        else:
            for e in exists:
                if certificate.get("external_id"):
                    e.external_id = certificate["external_id"]
                if certificate.get("authority_id"):
                    e.authority_id = certificate["authority_id"]
                certificate_update(e, source)
                updated += 1

    return new, updated


def sync(source, user):
    new_certs, updated_certs = sync_certificates(source, user)
    new_endpoints, updated_endpoints = sync_endpoints(source)

    source.last_run = arrow.utcnow()
    database.update(source)

    return {
        "endpoints": (new_endpoints, updated_endpoints),
        "certificates": (new_certs, updated_certs),
    }


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
    source = Source(
        label=label, options=options, plugin_name=plugin_name, description=description
    )
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
    return database.get(Source, label, field="label")


def get_all():
    """
    Retrieves all source currently known by Lemur.

    :return:
    """
    query = database.session_query(Source)
    return database.find_all(query, Source, {}).all()


def render(args):
    filt = args.pop("filter")
    certificate_id = args.pop("certificate_id", None)

    if certificate_id:
        query = database.session_query(Source).join(Certificate, Source.certificate)
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Source)

    if filt:
        terms = filt.split(";")
        query = database.filter(query, Source, terms)

    return database.sort_and_page(query, Source, args)


def add_aws_destination_to_sources(dst):
    """
    Given a destination check, if it can be added as sources, and included it if not already a source
    We identify qualified destinations based on the sync_as_source attributed of the plugin.
    The destination sync_as_source_name reveals the name of the suitable source-plugin.
    We rely on account numbers to avoid duplicates.
    :return: true for success and false for not adding the destination as source
    """
    # a set of all accounts numbers available as sources
    src_accounts = set()
    sources = get_all()
    for src in sources:
        src_accounts.add(get_plugin_option("accountNumber", src.options))

    # check
    destination_plugin = plugins.get(dst.plugin_name)
    account_number = get_plugin_option("accountNumber", dst.options)
    if (
        account_number is not None
        and destination_plugin.sync_as_source is not None
        and destination_plugin.sync_as_source
        and (account_number not in src_accounts)
    ):
        src_options = copy.deepcopy(
            plugins.get(destination_plugin.sync_as_source_name).options
        )
        set_plugin_option("accountNumber", account_number, src_options)
        create(
            label=dst.label,
            plugin_name=destination_plugin.sync_as_source_name,
            options=src_options,
            description=dst.description,
        )
        return True

    return False
