"""
.. module: lemur.destinations.service
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import func
from flask import current_app

from lemur import database
from lemur.models import certificate_destination_associations
from lemur.destinations.models import Destination
from lemur.certificates.models import Certificate
from lemur.certificates import service as certificate_service
from lemur.logs import service as log_service
from lemur.sources.service import add_aws_destination_to_sources


def create(label, plugin_name, options, description=None):
    """
    Creates a new destination, that can then be used as a destination for certificates.

    :param label: Destination common name
    :param description:
    :rtype: Destination
    :return: New destination
    """
    # remove any sub-plugin objects before try to save the json options
    for option in options:
        if "plugin" in option["type"]:
            del option["value"]["plugin_object"]

    destination = Destination(
        label=label, options=options, plugin_name=plugin_name, description=description
    )
    current_app.logger.info("Destination: %s created", label)

    # add the destination as source, to avoid new destinations that are not in source, as long as an AWS destination
    if add_aws_destination_to_sources(destination):
        current_app.logger.info("Source: %s created", label)

    log_service.audit_log("create_destination", destination.label, "Creating new destination")
    return database.create(destination)


def update(destination_id, label, plugin_name, options, description):
    """
    Updates an existing destination.

    :param destination_id:  Lemur assigned ID
    :param label: Destination common name
    :param plugin_name:
    :param options:
    :param description:
    :rtype: Destination
    :return:
    """
    destination = get(destination_id)

    destination.label = label
    destination.plugin_name = plugin_name
    # remove any sub-plugin objects before try to save the json options
    for option in options:
        if "plugin" in option["type"]:
            del option["value"]["plugin_object"]
    destination.options = options
    destination.description = description

    log_service.audit_log("update_destination", destination.label, "Updating destination")
    updated = database.update(destination)
    # add the destination as source, to avoid new destinations that are not in source, as long as an AWS destination
    if add_aws_destination_to_sources(updated):
        current_app.logger.info("Source: %s created", label)
    return updated


def delete(destination_id):
    """
    Deletes an destination.

    :param destination_id: Lemur assigned ID
    """
    destination = get(destination_id)
    if destination:
        # remove association of this source from all valid certificates
        certificates = certificate_service.get_all_valid_certificates_with_destination(destination_id)
        for certificate in certificates:
            certificate_service.remove_destination_association(certificate, destination)
            current_app.logger.warning(
                f"Removed destination {destination.label} for {certificate.name} during destination delete")

        # proceed with destination delete
        log_service.audit_log("delete_destination", destination.label, "Deleting destination")
        database.delete(destination)


def get(destination_id):
    """
    Retrieves an destination by its lemur assigned ID.

    :param destination_id: Lemur assigned ID
    :rtype: Destination
    :return:
    """
    return database.get(Destination, destination_id)


def get_by_label(label):
    """
    Retrieves a destination by its label

    :param label:
    :return:
    """
    return database.get(Destination, label, field="label")


def get_all():
    """
    Retrieves all destination currently known by Lemur.

    :return:
    """
    query = database.session_query(Destination)
    return database.find_all(query, Destination, {}).all()


def render(args):
    filt = args.pop("filter")
    certificate_id = args.pop("certificate_id", None)

    if certificate_id:
        query = database.session_query(Destination).join(
            Certificate, Destination.certificate
        )
        query = query.filter(Certificate.id == certificate_id)
    else:
        query = database.session_query(Destination)

    if filt:
        terms = filt.split(";")
        query = database.filter(query, Destination, terms)

    return database.sort_and_page(query, Destination, args)


def stats(**kwargs):
    """
    Helper that defines some useful statistics about destinations.

    :param kwargs:
    :return:
    """
    items = (
        database.db.session.query(
            Destination.label,
            func.count(certificate_destination_associations.c.certificate_id),
        )
        .join(certificate_destination_associations)
        .group_by(Destination.label)
        .all()
    )

    keys = []
    values = []
    for key, count in items:
        keys.append(key)
        values.append(count)

    return {"labels": keys, "values": values}
