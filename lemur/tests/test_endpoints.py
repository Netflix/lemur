import pytest

from lemur.endpoints.views import *  # noqa
from lemur.tests.factories import EndpointFactory, CertificateFactory


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_rotate_certificate(client, source_plugin):
    from lemur.deployment.service import rotate_certificate

    new_certificate = CertificateFactory()
    endpoint = EndpointFactory()

    rotate_certificate(endpoint, new_certificate)
    assert endpoint.certificate == new_certificate


def test_get_by_name_and_source(client, source_plugin):
    from lemur.endpoints.service import get_by_name_and_source

    endpoint = EndpointFactory()
    assert endpoint == get_by_name_and_source(endpoint.name, endpoint.source.label)


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_endpoint_get(client, token, status):
    assert (
        client.get(api.url_for(Endpoints, endpoint_id=999), headers=token).status_code
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
def test_endpoint_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
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
def test_endpoint_put(client, token, status):
    assert (
        client.put(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
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
def test_endpoint_delete(client, token, status):
    assert (
        client.delete(api.url_for(Endpoints, endpoint_id=1), headers=token).status_code
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
def test_endpoint_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
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
def test_endpoint_list_post_(client, token, status):
    assert (
        client.post(api.url_for(EndpointsList), data={}, headers=token).status_code
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
def test_endpoint_list_get(client, token, status):
    assert client.get(api.url_for(EndpointsList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(EndpointsList), headers=token).status_code == status
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
def test_endpoint_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(EndpointsList), data={}, headers=token).status_code
        == status
    )
