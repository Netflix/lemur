import pytest

from lemur.sources.views import *  # noqa

from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
    WILDCARD_CERT_STR,
    WILDCARD_CERT_KEY,
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
        (VALID_USER_HEADER_TOKEN, 400),
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
        (VALID_USER_HEADER_TOKEN, 400),
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
