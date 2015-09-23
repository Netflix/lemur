from __future__ import unicode_literals    # at top of module

import pytest
from lemur.certificates.views import *  # noqa


def test_pem_str():
    from lemur.tests.certs import INTERNAL_VALID_LONG_STR
    assert pem_str(INTERNAL_VALID_LONG_STR, 'test') == INTERNAL_VALID_LONG_STR

    with pytest.raises(ValueError):
        pem_str('sdfsdfds', 'test')


def test_private_key_str():
    from lemur.tests.certs import PRIVATE_KEY_STR
    assert private_key_str(PRIVATE_KEY_STR, 'test') == PRIVATE_KEY_STR

    with pytest.raises(ValueError):
        private_key_str('dfsdfsdf', 'test')


def test_create_basic_csr():
    from lemur.certificates.service import create_csr
    csr_config = dict(
        commonName='example.com',
        organization='Example, Inc.',
        organizationalUnit='Operations',
        country='US',
        state='CA',
        location='A place',
        extensions=dict(names=dict(subAltNames=['test.example.com', 'test2.example.com']))
    )
    csr, pem = create_csr(csr_config)

    private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    csr = x509.load_pem_x509_csr(csr, default_backend())
    for name in csr.subject:
        assert name.value in csr_config.values()


def test_cert_get_cn():
    from lemur.tests.certs import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_get_cn

    assert cert_get_cn(INTERNAL_VALID_LONG_CERT) == 'long.lived.com'


def test_cert_get_subAltDomains():
    from lemur.tests.certs import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_get_domains

    assert cert_get_domains(INTERNAL_VALID_LONG_CERT) == []
    assert cert_get_domains(INTERNAL_VALID_SAN_CERT) == ['example2.long.com', 'example3.long.com']


def test_cert_is_san():
    from lemur.tests.certs import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_is_san

    assert cert_is_san(INTERNAL_VALID_LONG_CERT) == None  # noqa
    assert cert_is_san(INTERNAL_VALID_SAN_CERT) == True  # noqa


def test_cert_is_wildcard():
    from lemur.tests.certs import INTERNAL_VALID_WILDCARD_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_is_wildcard
    assert cert_is_wildcard(INTERNAL_VALID_WILDCARD_CERT) == True  # noqa
    assert cert_is_wildcard(INTERNAL_VALID_LONG_CERT) == None  # noqa


def test_cert_get_bitstrength():
    from lemur.tests.certs import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_get_bitstrength
    assert cert_get_bitstrength(INTERNAL_VALID_LONG_CERT) == 2048


def test_cert_get_issuer():
    from lemur.tests.certs import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import cert_get_issuer
    assert cert_get_issuer(INTERNAL_VALID_LONG_CERT) == 'Example'


def test_get_name_from_arn():
    from lemur.certificates.models import get_name_from_arn
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_name_from_arn(arn) == 'mycertificate'


def test_get_account_number():
    from lemur.certificates.models import get_account_number
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_account_number(arn) == '11111111'


def test_create_name():
    from lemur.certificates.models import create_name
    from datetime import datetime
    assert create_name(
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        'example.com',
        False
    ) == 'example.com-ExampleInc-20150507-20150512'
    assert create_name(
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        'example.com',
        True
    ) == 'SAN-example.com-ExampleInc-20150507-20150512'


def test_certificate_get(client):
    assert client.get(api.url_for(Certificates, certificate_id=1)).status_code == 401


def test_certificate_post(client):
    assert client.post(api.url_for(Certificates, certificate_id=1), data={}).status_code == 405


def test_certificate_put(client):
    assert client.put(api.url_for(Certificates, certificate_id=1), data={}).status_code == 401


def test_certificate_delete(client):
    assert client.delete(api.url_for(Certificates, certificate_id=1)).status_code == 405


def test_certificate_patch(client):
    assert client.patch(api.url_for(Certificates, certificate_id=1), data={}).status_code == 405


def test_certificates_get(client):
    assert client.get(api.url_for(CertificatesList)).status_code == 401


def test_certificates_post(client):
    assert client.post(api.url_for(CertificatesList), data={}).status_code == 401


def test_certificates_put(client):
    assert client.put(api.url_for(CertificatesList), data={}).status_code == 405


def test_certificates_delete(client):
    assert client.delete(api.url_for(CertificatesList)).status_code == 405


def test_certificates_patch(client):
    assert client.patch(api.url_for(CertificatesList), data={}).status_code == 405


def test_certificate_credentials_get(client):
    assert client.get(api.url_for(CertificatePrivateKey, certificate_id=1)).status_code == 401


def test_certificate_credentials_post(client):
    assert client.post(api.url_for(CertificatePrivateKey, certificate_id=1), data={}).status_code == 405


def test_certificate_credentials_put(client):
    assert client.put(api.url_for(CertificatePrivateKey, certificate_id=1), data={}).status_code == 405


def test_certificate_credentials_delete(client):
    assert client.delete(api.url_for(CertificatePrivateKey, certificate_id=1)).status_code == 405


def test_certificate_credentials_patch(client):
    assert client.patch(api.url_for(CertificatePrivateKey, certificate_id=1), data={}).status_code == 405


def test_certificates_upload_get(client):
    assert client.get(api.url_for(CertificatesUpload)).status_code == 405


def test_certificates_upload_post(client):
    assert client.post(api.url_for(CertificatesUpload), data={}).status_code == 401


def test_certificates_upload_put(client):
    assert client.put(api.url_for(CertificatesUpload), data={}).status_code == 405


def test_certificates_upload_delete(client):
    assert client.delete(api.url_for(CertificatesUpload)).status_code == 405


def test_certificates_upload_patch(client):
    assert client.patch(api.url_for(CertificatesUpload), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_certificate_get(client):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_certificate_post_(client):
    assert client.post(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificate_put(client):
    assert client.put(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_certificate_delete(client):
    assert client.delete(api.url_for(Certificates, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificate_patch(client):
    assert client.patch(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificates_get(client):
    assert client.get(api.url_for(CertificatesList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_certificates_post(client):
    assert client.post(api.url_for(CertificatesList), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_certificate_credentials_get(client):
    assert client.get(api.url_for(CertificatePrivateKey, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 404


def test_auth_certificate_credentials_post(client):
    assert client.post(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificate_credentials_put(client):
    assert client.put(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificate_credentials_delete(client):
    assert client.delete(api.url_for(CertificatePrivateKey, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificate_credentials_patch(client):
    assert client.patch(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificates_upload_get(client):
    assert client.get(api.url_for(CertificatesUpload), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificates_upload_post(client):
    assert client.post(api.url_for(CertificatesUpload), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 400


def test_auth_certificates_upload_put(client):
    assert client.put(api.url_for(CertificatesUpload), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificates_upload_delete(client):
    assert client.delete(api.url_for(CertificatesUpload), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_certificates_upload_patch(client):
    assert client.patch(api.url_for(CertificatesUpload), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_certificate_get(client):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_certificate_post(client):
    assert client.post(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_put(client):
    assert client.put(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 400


def test_admin_certificate_delete(client):
    assert client.delete(api.url_for(Certificates, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_patch(client):
    assert client.patch(api.url_for(Certificates, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificates_get(client):
    resp = client.get(api.url_for(CertificatesList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json['total'] == 0


def test_admin_certificate_credentials_get(client):
    assert client.get(api.url_for(CertificatePrivateKey, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 404


def test_admin_certificate_credentials_post(client):
    assert client.post(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_credentials_put(client):
    assert client.put(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_credentials_delete(client):
    assert client.delete(api.url_for(CertificatePrivateKey, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_certificate_credentials_patch(client):
    assert client.patch(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405
