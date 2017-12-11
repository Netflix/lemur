from lemur.pending_certificates.models import PendingCertificate


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
