from lemur.domains.views import *  # noqa


def test_domain_get(client):
    assert client.get(api.url_for(Domains, domain_id=1)).status_code == 401


def test_domain_post(client):
    assert client.post(api.url_for(Domains, domain_id=1), data={}).status_code == 405


def test_domain_put(client):
    assert client.put(api.url_for(Domains, domain_id=1), data={}).status_code == 405


def test_domain_delete(client):
    assert client.delete(api.url_for(Domains, domain_id=1)).status_code == 405


def test_domain_patch(client):
    assert client.patch(api.url_for(Domains, domain_id=1), data={}).status_code == 405


VALID_USER_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyMzMzNjksInN1YiI6MSwiZXhwIjoxNTIxNTQ2OTY5fQ.1qCi0Ip7mzKbjNh0tVd3_eJOrae3rNa_9MCVdA4WtQI'}


def test_auth_domain_get(client):
    assert client.get(api.url_for(Domains, domain_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_auth_domain_post_(client):
    assert client.post(api.url_for(Domains, domain_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_domain_put(client):
    assert client.put(api.url_for(Domains, domain_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_domain_delete(client):
    assert client.delete(api.url_for(Domains, domain_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 405


def test_auth_domain_patch(client):
    assert client.patch(api.url_for(Domains, domain_id=1), data={}, headers=VALID_USER_HEADER_TOKEN).status_code == 405


VALID_ADMIN_HEADER_TOKEN = {
    'Authorization': 'Basic ' + 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MzUyNTAyMTgsInN1YiI6MiwiZXhwIjoxNTIxNTYzODE4fQ.6mbq4-Ro6K5MmuNiTJBB153RDhlM5LGJBjI7GBKkfqA'}


def test_admin_domain_get(client):
    assert client.get(api.url_for(Domains, domain_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200


def test_admin_domain_post(client):
    assert client.post(api.url_for(Domains, domain_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_domain_put(client):
    assert client.put(api.url_for(Domains, domain_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_domain_delete(client):
    assert client.delete(api.url_for(Domains, domain_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_admin_domain_patch(client):
    assert client.patch(api.url_for(Domains, domain_id=1), data={}, headers=VALID_ADMIN_HEADER_TOKEN).status_code == 405


def test_domains_get(client):
    assert client.get(api.url_for(DomainsList)).status_code == 401


def test_domains_post(client):
    assert client.post(api.url_for(DomainsList), data={}).status_code == 405


def test_domains_put(client):
    assert client.put(api.url_for(DomainsList), data={}).status_code == 405


def test_domains_delete(client):
    assert client.delete(api.url_for(DomainsList)).status_code == 405


def test_domains_patch(client):
    assert client.patch(api.url_for(DomainsList), data={}).status_code == 405


def test_auth_domains_get(client):
    assert client.get(api.url_for(DomainsList), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_admin_domains_get(client):
    resp = client.get(api.url_for(DomainsList), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    assert resp.json == {'items': [], 'total': 0}


def test_certificate_domains_get(client):
    assert client.get(api.url_for(CertificateDomains, certificate_id=1)).status_code == 401


def test_certificate_domains_post(client):
    assert client.post(api.url_for(CertificateDomains, certificate_id=1), data={}).status_code == 405


def test_certificate_domains_put(client):
    assert client.put(api.url_for(CertificateDomains, certificate_id=1), data={}).status_code == 405


def test_certificate_domains_delete(client):
    assert client.delete(api.url_for(CertificateDomains, certificate_id=1)).status_code == 405


def test_certificate_domains_patch(client):
    assert client.patch(api.url_for(CertificateDomains, certificate_id=1), data={}).status_code == 405


def test_auth_certificate_domains_get(client):
    assert client.get(api.url_for(CertificateDomains, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).status_code == 200


def test_admin_certificate_domains_get(client):
    assert client.get(api.url_for(CertificateDomains, certificate_id=1), headers=VALID_ADMIN_HEADER_TOKEN).status_code == 200
