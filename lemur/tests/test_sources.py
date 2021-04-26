import pytest

from lemur.sources.views import *  # noqa

from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
    WILDCARD_CERT_STR,
    WILDCARD_CERT_KEY,
    SAN_CERT_STR,
)


def validate_source_schema(client):
    from lemur.sources.schemas import SourceInputSchema

    input_data = {
        "label": "exampleSource",
        "options": {},
        "plugin": {"slug": "aws-source"},
    }

    data, errors = SourceInputSchema().load(input_data)
    assert not errors


def test_create_certificate(user, source):
    from lemur.sources.service import certificate_create

    with pytest.raises(Exception):
        certificate_create({}, source)

    data = {
        "body": WILDCARD_CERT_STR,
        "private_key": WILDCARD_CERT_KEY,
        "owner": "bob@example.com",
        "creator": user["user"],
    }

    cert = certificate_create(data, source)
    assert cert.notifications


def test_sync_certificates_same_cert_different_name(user, source, sync_source_plugin):
    from lemur.sources.service import sync_certificates, certificate_create
    from lemur.certificates import service as cert_service
    from lemur.plugins.base import plugins

    # create an existing cert with same body
    data = {
        "body": WILDCARD_CERT_STR,
        "private_key": WILDCARD_CERT_KEY,
        "owner": "bob@example.com",
        "creator": user["user"],
    }
    certificate_create(data, source)

    # sync a certificate with same body
    s = plugins.get(source.plugin_name)
    s.certificates = [
        {
            "name": "WildcardCert1",
            "body": WILDCARD_CERT_STR,
        },
    ]

    res = sync_certificates(source, user["user"])

    assert res == (1, 0, 0)
    assert cert_service.get_by_name("WildcardCert1") is not None


def test_sync_certificates_same_cert_same_name(user, source, sync_source_plugin):
    from lemur.sources.service import sync_certificates, certificate_create
    from lemur.certificates import service as cert_service
    from lemur.plugins.base import plugins

    # create an existing cert with same body
    data = {
        "name": "WildcardCert2",
        "body": WILDCARD_CERT_STR,
        "private_key": WILDCARD_CERT_KEY,
        "owner": "bob@example.com",
        "creator": user["user"],
    }
    certificate_create(data, source)

    # sync a certificate with same body
    s = plugins.get(source.plugin_name)
    s.certificates = [
        {
            "name": "WildcardCert2",
            "body": WILDCARD_CERT_STR,
        },
    ]

    res = sync_certificates(source, user["user"])

    assert res == (0, 1, 1)
    assert cert_service.get_by_name("WildcardCert2") is not None


def test_sync_certificates_different_cert_existing_name(user, source, sync_source_plugin):
    from lemur.sources.service import sync_certificates, certificate_create
    from lemur.certificates import service as cert_service
    from lemur.plugins.base import plugins

    # create an existing cert with same body
    data = {
        "name": "MyCert1",
        "body": WILDCARD_CERT_STR,
        "private_key": WILDCARD_CERT_KEY,
        "owner": "bob@example.com",
        "creator": user["user"],
    }
    certificate_create(data, source)

    # sync a certificate with same body
    s = plugins.get(source.plugin_name)
    s.certificates = [
        {
            "name": "MyCert1",
            "body": SAN_CERT_STR,
        },
    ]

    with pytest.raises(Exception):
        sync_certificates(source, user["user"])


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_source_get(client, source_plugin, token, status):
    assert (
        client.get(api.url_for(Sources, source_id=43543), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_source_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_source_put(client, token, status):
    assert (
        client.put(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_source_delete(client, token, status):
    assert (
        client.delete(api.url_for(Sources, source_id=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_source_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Sources, source_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_sources_list_get(client, source_plugin, token, status):
    assert client.get(api.url_for(SourcesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_sources_list_post(client, token, status):
    assert (
        client.post(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_put(client, token, status):
    assert (
        client.put(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_delete(client, token, status):
    assert client.delete(api.url_for(SourcesList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_sources_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(SourcesList), data={}, headers=token).status_code
        == status
    )
