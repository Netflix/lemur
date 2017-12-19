from .vectors import CSR_STR, INTERNAL_VALID_LONG_STR


def test_increment_attempt(pending_certificate):
    from lemur.pending_certificates.service import increment_attempt
    initial_attempt = pending_certificate.number_attempts
    attempts = increment_attempt(pending_certificate)
    assert attempts == initial_attempt + 1


def test_create_pending_certificate(async_issuer_plugin, async_authority, user):
    from lemur.certificates.service import create
    pending_cert = create(authority=async_authority, csr=CSR_STR, owner='joe@example.com', creator=user['user'], common_name='ACommonName')
    assert pending_cert.external_id == '12345'


def test_create_pending(pending_certificate, user, session):
    from lemur.pending_certificates.service import create_certificate, get
    cert = {'body': INTERNAL_VALID_LONG_STR,
            'chain': None,
            'external_id': 54321}

    # weird hack, pending_certificate is part of some session from fixtures, so get it again then
    # detach pending_cert from session, because passing it inside test scope breaks its __dict__,
    # which means the resulting Certificate will not update its values
    pending_certificate = get(pending_certificate.id)
    session.expunge(pending_certificate)
    real_cert = create_certificate(pending_certificate, cert, user['user'])
    assert real_cert.owner == pending_certificate.owner
    assert real_cert.notify == pending_certificate.notify
    assert real_cert.private_key == pending_certificate.private_key
    assert real_cert.external_id == '54321'
