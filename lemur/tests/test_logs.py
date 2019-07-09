import pytest
from lemur.tests.vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)

from lemur.logs.views import *  # noqa


def test_private_key_audit(client, certificate):
    from lemur.certificates.views import CertificatePrivateKey, api

    assert len(certificate.logs) == 0
    client.get(
        api.url_for(CertificatePrivateKey, certificate_id=certificate.id),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert len(certificate.logs) == 1


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_get_logs(client, token, status):
    assert client.get(api.url_for(LogsList), headers=token).status_code == status
