"""
.. module: lemur.pending_certificates.service
    Copyright (c) 2018 and onwards Netflix, Inc.  All rights reserved.
.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""
import arrow
from sqlalchemy import or_, cast, Integer
from flask import current_app

from lemur import database
from lemur.authorities.models import Authority
from lemur.authorities import service as authorities_service
from lemur.certificates import service as certificate_service
from lemur.certificates.schemas import CertificateUploadInputSchema
from lemur.common.utils import truthiness, parse_cert_chain, parse_certificate
from lemur.common import validators
from lemur.destinations.models import Destination
from lemur.domains.models import Domain
from lemur.extensions import metrics
from lemur.notifications.models import Notification
from lemur.pending_certificates.models import PendingCertificate
from lemur.plugins.base import plugins
from lemur.roles.models import Role
from lemur.users import service as user_service
from lemur.logs import service as log_service


def get(pending_cert_id):
    """
    Retrieve pending certificate by ID
    """
    return database.get(PendingCertificate, pending_cert_id)


def get_by_external_id(issuer, external_id):
    """
    Retrieves a pending certificate by its issuer and external_id
    Since external_id is not necessarily unique between CAs

    :param issuer:
    :param external_id:
    :return: PendingCertificate or None
    """
    if isinstance(external_id, int):
        external_id = str(external_id)
    return (
        PendingCertificate.query.filter(PendingCertificate.authority_id == issuer.id)
        .filter(PendingCertificate.external_id == external_id)
        .one_or_none()
    )


def get_by_name(pending_cert_name):
    """
    Retrieve pending certificate by name
    """
    return database.get(PendingCertificate, pending_cert_name, field="name")


def delete(pending_certificate):
    log_service.audit_log("delete_pending_certificate", pending_certificate.name, "Deleting the pending certificate")
    database.delete(pending_certificate)


def delete_by_id(id):
    delete(get(id))


def get_unresolved_pending_certs():
    """
    Retrieve a list of unresolved pending certs given a list of ids
    Filters out non-existing pending certs
    """
    query = database.session_query(PendingCertificate).filter(
        PendingCertificate.resolved.is_(False)
    )
    return database.find_all(query, PendingCertificate, {}).all()


def get_pending_certs(pending_ids):
    """
    Retrieve a list of pending certs given a list of ids
    Filters out non-existing pending certs
    """
    pending_certs = []
    if "all" in pending_ids:
        query = database.session_query(PendingCertificate)
        return database.find_all(query, PendingCertificate, {}).all()
    else:
        for pending_id in pending_ids:
            pending_cert = get(pending_id)
            if pending_cert:
                pending_certs.append(pending_cert)
    return pending_certs


def create_certificate(pending_certificate, certificate, user):
    """
    Create and store a certificate with pending certificate's info

    :arg pending_certificate: PendingCertificate which will populate the certificate
    :arg certificate: dict from Authority, which contains the body, chain and external id
    :arg user: User that called this function, used as 'creator' of the certificate if it does not have an owner
    """
    certificate["owner"] = pending_certificate.owner
    data, errors = CertificateUploadInputSchema().load(certificate)
    if errors:
        raise Exception(
            f"Unable to create certificate: {errors}"
        )

    data.update(vars(pending_certificate))
    # Copy relationships, vars doesn't copy this without explicit fields
    data["notifications"] = list(pending_certificate.notifications)
    data["destinations"] = list(pending_certificate.destinations)
    data["sources"] = list(pending_certificate.sources)
    data["roles"] = list(pending_certificate.roles)
    data["replaces"] = list(pending_certificate.replaces)
    data["rotation_policy"] = pending_certificate.rotation_policy

    # Replace external id and chain with the one fetched from source
    data["external_id"] = certificate["external_id"]
    data["chain"] = certificate["chain"]
    creator = user_service.get_by_email(pending_certificate.owner)
    if not creator:
        # Owner of the pending certificate is not the creator, so use the current user who called
        # this as the creator (usually lemur)
        creator = user

    if pending_certificate.rename:
        # If generating name from certificate, remove the one from pending certificate
        del data["name"]
    data["creator"] = creator

    cert = certificate_service.import_certificate(**data)
    database.update(cert)

    metrics.send("certificate_issued", "counter", 1, metric_tags=dict(owner=cert.owner, issuer=cert.issuer))
    log_service.audit_log("certificate_from_pending_certificate", cert.name,
                          f"Created from the pending certificate {pending_certificate.name}")
    log_data = {
        "function": "lemur.certificates.service.create",
        "owner": cert.owner,
        "name": cert.name,
        "serial": cert.serial,
        "issuer": cert.issuer,
        "not_after": cert.not_after.format('YYYY-MM-DD HH:mm:ss'),
        "not_before": cert.not_before.format('YYYY-MM-DD HH:mm:ss'),
        "sans": cert.san,
    }
    current_app.logger.info(log_data)
    return cert


def increment_attempt(pending_certificate):
    """
    Increments pending certificate attempt counter and updates it in the database.
    """
    pending_certificate.number_attempts += 1
    database.update(pending_certificate)

    log_service.audit_log("increment_attempt_pending_certificate", pending_certificate.name,
                          "Incremented attempts for the pending certificate")
    return pending_certificate.number_attempts


def update(pending_cert_id, **kwargs):
    """
    Updates a pending certificate.  The allowed fields are validated by
    PendingCertificateEditInputSchema.
    """
    pending_cert = get(pending_cert_id)
    for key, value in kwargs.items():
        setattr(pending_cert, key, value)

    log_service.audit_log("update_pending_certificate", pending_cert.name, f"Update summary - {kwargs}")
    return database.update(pending_cert)


def cancel(pending_certificate, **kwargs):
    """
    Cancel a pending certificate.  A check should be done prior to this function to decide to
    revoke the certificate or just abort cancelling.

    :arg pending_certificate: PendingCertificate to be cancelled
    :return: the pending certificate if successful, raises Exception if there was an issue
    """
    plugin = plugins.get(pending_certificate.authority.plugin_name)
    plugin.cancel_ordered_certificate(pending_certificate, **kwargs)
    pending_certificate.status = "Cancelled"
    database.update(pending_certificate)

    log_service.audit_log("cancel_pending_certificate", pending_certificate.name, "Cancelled the pending certificate")
    return pending_certificate


def render(args):
    query = database.session_query(PendingCertificate)
    time_range = args.pop("time_range")
    destination_id = args.pop("destination_id")
    notification_id = args.pop("notification_id", None)
    show = args.pop("show")
    # owner = args.pop('owner')
    # creator = args.pop('creator')  # TODO we should enabling filtering by owner

    filt = args.pop("filter")

    if filt:
        terms = filt.split(";")

        if "issuer" in terms:
            # we can't rely on issuer being correct in the cert directly so we combine queries
            sub_query = (
                database.session_query(Authority.id)
                .filter(Authority.name.ilike(f"%{terms[1]}%"))
                .subquery()
            )

            query = query.filter(
                or_(
                    PendingCertificate.issuer.ilike(f"%{terms[1]}%"),
                    PendingCertificate.authority_id.in_(sub_query),
                )
            )

        elif "destination" in terms:
            query = query.filter(
                PendingCertificate.destinations.any(Destination.id == terms[1])
            )
        elif "notify" in filt:
            query = query.filter(PendingCertificate.notify == truthiness(terms[1]))
        elif "active" in filt:
            query = query.filter(PendingCertificate.active == truthiness(terms[1]))
        elif "cn" in terms:
            query = query.filter(
                or_(
                    PendingCertificate.cn.ilike(f"%{terms[1]}%"),
                    PendingCertificate.domains.any(
                        Domain.name.ilike(f"%{terms[1]}%")
                    ),
                )
            )
        elif "id" in terms:
            query = query.filter(PendingCertificate.id == cast(terms[1], Integer))
        else:
            query = database.filter(query, PendingCertificate, terms)

    if show:
        sub_query = (
            database.session_query(Role.name)
            .filter(Role.user_id == args["user"].id)
            .subquery()
        )
        query = query.filter(
            or_(
                PendingCertificate.user_id == args["user"].id,
                PendingCertificate.owner.in_(sub_query),
            )
        )

    if destination_id:
        query = query.filter(
            PendingCertificate.destinations.any(Destination.id == destination_id)
        )

    if notification_id:
        query = query.filter(
            PendingCertificate.notifications.any(Notification.id == notification_id)
        )

    if time_range:
        to = arrow.now().shift(weeks=+time_range).format("YYYY-MM-DD")
        now = arrow.now().format("YYYY-MM-DD")
        query = query.filter(PendingCertificate.not_after <= to).filter(
            PendingCertificate.not_after >= now
        )

    # Only show unresolved certificates in the UI
    query = query.filter(PendingCertificate.resolved.is_(False))
    return database.sort_and_page(query, PendingCertificate, args)


def upload(pending_certificate_id, **kwargs):
    """
    Uploads a (signed) pending certificate. The allowed fields are validated by
    PendingCertificateUploadInputSchema. The certificate is also validated to be
    signed by the correct authority.
    """
    pending_cert = get(pending_certificate_id)
    partial_cert = kwargs
    uploaded_chain = partial_cert["chain"]

    authority = authorities_service.get(pending_cert.authority.id)

    # Construct the chain for cert validation
    if uploaded_chain:
        chain = uploaded_chain + "\n" + authority.authority_certificate.body
    else:
        chain = authority.authority_certificate.body

    parsed_chain = parse_cert_chain(chain)

    # Check that the certificate is actually signed by the CA to avoid incorrect cert pasting
    validators.verify_cert_chain(
        [parse_certificate(partial_cert["body"])] + parsed_chain
    )

    final_cert = create_certificate(pending_cert, partial_cert, pending_cert.user)

    pending_cert_final_result = update(pending_cert.id, resolved_cert_id=final_cert.id)
    update(pending_cert.id, resolved=True)

    log_service.audit_log("resolve_pending_certificate", pending_cert.name, "Resolved the pending certificate")

    return pending_cert_final_result
