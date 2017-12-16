"""
.. module: lemur.pending_certificates.service
    Copyright (c) 2017 and onwards Instart Logic, Inc.  All rights reserved.
.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""
from lemur import database

from lemur.certificates import service as certificate_service
from lemur.users import service as user_service

from lemur.certificates.schemas import CertificateUploadInputSchema
from lemur.pending_certificates.models import PendingCertificate


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
    return PendingCertificate.query \
        .filter(PendingCertificate.authority_id == issuer.id) \
        .filter(PendingCertificate.external_id == external_id) \
        .one_or_none()


def delete(pending_certificate):
    database.delete(pending_certificate)


def get_pending_certs(pending_ids):
    """
    Retrieve a list of pending certs given a list of ids
    Filters out non-existing pending certs
    """
    pending_certs = []
    if 'all' in pending_ids:
        query = database.session_query(PendingCertificate)
        return database.find_all(query, PendingCertificate, {}).all()
    else:
        for pending_id in pending_ids:
            pending_cert = get(pending_id)
            if pending_cert:
                pending_certs.append(pending_cert)
    return pending_certs


def create_certificate(pending_certificate, certificate):
    """
    Create and store a certificate with pending certificate's info
    """
    certificate['owner'] = pending_certificate.owner
    data, errors = CertificateUploadInputSchema().load(certificate)
    if errors:
        raise Exception("Unable to create certificate: {reasons}".format(reasons=errors))

    data.update(vars(pending_certificate))
    # Replace external id with the one fetched from source
    data['external_id'] = certificate['external_id']
    creator = user_service.get_by_email(pending_certificate.owner)
    if not creator:
        # Owner of the pending certificate is not the 'owner', and does not exist as a user
        creator = user_service.get_by_username("lemur")
    data['creator'] = creator
    cert = certificate_service.import_certificate(**data)
    database.update(cert)
    return cert


def increment_attempt(pending_certificate):
    pending_certificate.number_attempts += 1
    database.update(pending_certificate)
    return pending_certificate.number_attempts
