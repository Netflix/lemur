"""
.. module: lemur.sources.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
from datetime import timedelta
import copy

from flask import current_app
from sqlalchemy.exc import OperationalError
from sentry_sdk import capture_exception
from sqlalchemy import cast
from sqlalchemy_utils import ArrowType

from lemur import database
from lemur.sources.models import Source
from lemur.certificates.models import Certificate
from lemur.certificates import service as certificate_service
from lemur.endpoints import service as endpoint_service
from lemur.endpoints.models import Endpoint
from lemur.extensions import metrics
from lemur.destinations import service as destination_service

from lemur.certificates.schemas import CertificateUploadInputSchema
from lemur.common.utils import find_matching_certificates_by_hash, parse_certificate
from lemur.common.defaults import serial
from lemur.logs import service as log_service
from lemur.plugins.base import plugins
from lemur.plugins.utils import get_plugin_option, set_plugin_option


def certificate_create(certificate, source):
    data, errors = CertificateUploadInputSchema().load(certificate)

    if errors:
        raise Exception(
            f"Unable to import certificate: {errors}"
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
    new, updated, updated_by_hash = 0, 0, 0
    current_app.logger.debug(f"Retrieving endpoints from {source.label}")
    s = plugins.get(source.plugin_name)

    try:
        endpoints = s.get_endpoints(source.options)
    except NotImplementedError:
        current_app.logger.warning(
            "Unable to sync endpoints for source {} plugin has not implemented 'get_endpoints'".format(
                source.label
            )
        )
        return new, updated, updated_by_hash

    for endpoint in endpoints:
        try:
            exists = endpoint_service.get_by_dnsname_and_port(
                endpoint["dnsname"], endpoint["port"]
            )
        except OperationalError as e:
            # This is a workaround for handling sqlalchemy error "idle-in-transaction timeout", which is seen rarely
            # during the sync of sources with few thousands of resources. The DB interaction may need a rewrite to
            # avoid prolonged idle transactions.
            if e.connection_invalidated:
                # all the update, insert operations are committed individually. So this should be harmless/no-op
                database.rollback()
                # retry one more time
                exists = endpoint_service.get_by_dnsname_and_port(
                    endpoint["dnsname"], endpoint["port"]
                )
            else:
                raise e

        certificate_name = endpoint.pop("certificate_name")

        endpoint["certificate"] = certificate_service.get_by_name(certificate_name)

        # if get cert by name failed, we attempt a search via serial number and hash comparison
        # and link the endpoint certificate to Lemur certificate
        if not endpoint["certificate"]:
            certificate_attached_to_endpoint = None
            try:
                certificate_attached_to_endpoint = s.get_certificate_by_name(certificate_name, source.options)
            except NotImplementedError:
                current_app.logger.warning(
                    "Unable to describe server certificate for endpoints in source {}:"
                    " plugin has not implemented 'get_certificate_by_name'".format(
                        source.label
                    )
                )
                capture_exception()

            if certificate_attached_to_endpoint:
                lemur_matching_cert, updated_by_hash_tmp = find_cert(certificate_attached_to_endpoint)
                updated_by_hash += updated_by_hash_tmp

                if lemur_matching_cert:
                    endpoint["certificate"] = lemur_matching_cert[0]

                if len(lemur_matching_cert) > 1:
                    current_app.logger.error(
                        "Too Many Certificates Found{}. Name: {} Endpoint: {}".format(
                            len(lemur_matching_cert), certificate_name, endpoint["name"]
                        )
                    )
                    metrics.send("endpoint.certificate.conflict",
                                 "gauge", len(lemur_matching_cert),
                                 metric_tags={"cert": certificate_name, "endpoint": endpoint["name"],
                                              "acct": s.get_option("accountNumber", source.options)})

        if not endpoint["certificate"]:
            current_app.logger.error({
                "message": "Certificate Not Found",
                "certificate_name": certificate_name,
                "endpoint_name": endpoint["name"],
                "dns_name": endpoint.get("dnsname"),
                "account": s.get_option("accountNumber", source.options),
            })

            metrics.send("endpoint.certificate.not.found",
                         "counter", 1,
                         metric_tags={"cert": certificate_name, "endpoint": endpoint["name"],
                                      "acct": s.get_option("accountNumber", source.options),
                                      "dnsname": endpoint.get("dnsname")})
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
            current_app.logger.debug(f"Endpoint Updated: {endpoint}")
            endpoint_service.update(exists.id, **endpoint)
            updated += 1

    return new, updated, updated_by_hash


def expire_endpoints(source, ttl_hours):
    now = arrow.utcnow()
    expiration = now - timedelta(hours=ttl_hours)
    endpoints = database.session_query(Endpoint).filter(Endpoint.source_id == source.id).filter(
        cast(Endpoint.last_updated, ArrowType) <= expiration
    )
    expired = 0
    for endpoint in endpoints:
        current_app.logger.info(
            f"Expiring endpoint from source {source.label}: {endpoint.name} Last Updated: {endpoint.last_updated}")
        database.delete(endpoint)
        metrics.send("endpoint_expired", "counter", 1,
                     metric_tags={"source": source.label, "endpoint": endpoint.dnsname})
        expired += 1
    return expired


def find_cert(certificate):
    updated_by_hash = 0
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
        updated_by_hash += 1

    exists = [x for x in exists if x]
    return exists, updated_by_hash


# TODO this is very slow as we don't batch update certificates
def sync_certificates(source, user):
    new, updated, updated_by_hash, unlinked = 0, 0, 0, 0

    current_app.logger.debug(f"Retrieving certificates from {source.label}")
    s = plugins.get(source.plugin_name)
    certificates = s.get_certificates(source.options)

    # emitting the count of certificates on the source
    metrics.send("sync_certificates_count",
                 "gauge", len(certificates),
                 metric_tags={"source": source.label})

    existing_certificates_with_source_by_id = {}
    for e in certificate_service.get_all_valid_certificates_with_source(source.id):
        existing_certificates_with_source_by_id[e.id] = e

    for certificate in certificates:
        exists, updated_by_hash = find_cert(certificate)

        if not certificate.get("owner"):
            certificate["owner"] = user.email

        certificate["creator"] = user

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
                if e.id in existing_certificates_with_source_by_id:
                    del existing_certificates_with_source_by_id[e.id]
                updated += 1

    # remove source from any certificates no longer being reported by it
    destination = destination_service.get_by_label(source.label)
    for certificate in existing_certificates_with_source_by_id.values():
        certificate_service.remove_source_association(certificate, source)
        current_app.logger.warning(f"Removed source {source.label} for {certificate.name} during source sync")
        if destination in certificate.destinations:
            certificate_service.remove_destination_association(certificate, destination, clean=False)
            current_app.logger.warning(f"Removed destination {source.label} for {certificate.name} during source sync")
        updated += 1
        unlinked += 1

    metrics.send("sync_certificates_unlinked",
                 "gauge", unlinked,
                 metric_tags={"source": source.label})

    return new, updated, updated_by_hash


def sync(source, user, ttl_hours=2):
    try:
        new_certs, updated_certs, updated_certs_by_hash = sync_certificates(source, user)
        metrics.send("sync.updated_certs_by_hash",
                     "gauge", updated_certs_by_hash,
                     metric_tags={"source": source.label})

        new_endpoints, updated_endpoints, updated_endpoints_by_hash = sync_endpoints(source)
        metrics.send("sync.updated_endpoints_by_hash",
                     "gauge", updated_endpoints_by_hash,
                     metric_tags={"source": source.label})

        expired_endpoints = expire_endpoints(source, ttl_hours)

        source.last_run = arrow.utcnow()
        database.update(source)

        return {
            "endpoints": (new_endpoints, updated_endpoints, expired_endpoints),
            "certificates": (new_certs, updated_certs),
        }
    except Exception as e:  # noqa
        current_app.logger.warning(f"Sync source '{source.label}' aborted: {e}")
        capture_exception()
        raise e


def create(label, plugin_name, options, description=None):
    """
    Creates a new source, that can then be used as a source for certificates.

    :param label: Source common name
    :param plugin_name:
    :param options:
    :param description:
    :rtype: Source
    :return: New source
    """
    source = Source(
        label=label, options=options, plugin_name=plugin_name, description=description
    )
    log_service.audit_log("create_source", source.label, "Creating new source")
    return database.create(source)


def update(source_id, label, plugin_name, options, description):
    """
    Updates an existing source.

    :param source_id:  Lemur assigned ID
    :param label: Source common name
    :param options:
    :param plugin_name:
    :param description:
    :rtype: Source
    :return:
    """
    source = get(source_id)

    source.label = label
    source.plugin_name = plugin_name
    source.options = options
    source.description = description

    log_service.audit_log("update_source", source.label, "Updating source")
    return database.update(source)


def delete(source_id):
    """
    Deletes an source.

    :param source_id: Lemur assigned ID
    """
    source = get(source_id)
    if source:
        # remove association of this source from all valid certificates
        certificates = certificate_service.get_all_valid_certificates_with_source(source_id)
        for certificate in certificates:
            certificate_service.remove_source_association(certificate, source)
            current_app.logger.warning(f"Removed source {source.label} for {certificate.name} during source delete")

        # proceed with source delete
        log_service.audit_log("delete_source", source.label, "Deleting source")
        database.delete(source)


def get(source_id):
    """
    Retrieves an source by its lemur assigned ID.

    :param source_id: Lemur assigned ID
    :rtype: Source
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
    Given a destination, check if it can be added as sources, and include it if not already a source
    We identify qualified destinations based on the sync_as_source attributed of the plugin.
    The destination sync_as_source_name reveals the name of the suitable source-plugin.
    We rely on account numbers to avoid duplicates.
    :return: true for success and false for not adding the destination as source
    """
    # check that destination can be synced to a source
    destination_plugin = plugins.get(dst.plugin_name)
    if destination_plugin.sync_as_source is None or not destination_plugin.sync_as_source:
        return False
    account_number = get_plugin_option("accountNumber", dst.options)
    if account_number is None:
        return False
    path = get_plugin_option("path", dst.options)
    if path is None:
        return False

    # a set of all (account number, path) available as sources
    src_account_paths = set()
    sources = get_all()
    for src in sources:
        src_account_paths.add(
            (get_plugin_option("accountNumber", src.options), get_plugin_option("path", src.options))
        )

    if (account_number, path) not in src_account_paths:
        src_options = copy.deepcopy(
            plugins.get(destination_plugin.sync_as_source_name).options
        )
        set_plugin_option("accountNumber", account_number, src_options)
        set_plugin_option("path", path, src_options)
        # Set the right endpointType for cloudfront sources.
        if get_plugin_option("endpointType", src_options) is not None and path == "/cloudfront/":
            set_plugin_option("endpointType", "cloudfront", src_options)
        create(
            label=dst.label,
            plugin_name=destination_plugin.sync_as_source_name,
            options=src_options,
            description=dst.description,
        )
        return True

    return False
