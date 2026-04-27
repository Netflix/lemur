import pytest

from lemur.destinations.views import *  # noqa


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_invalid_label():
    from lemur.destinations.models import Destination
    with pytest.raises(ValueError) as e:
        Destination(label="too_long" * 50)
    assert "Label exceeds max length" in str(e)


def test_destination_input_schema(client, destination_plugin, destination):
    from lemur.destinations.schemas import DestinationInputSchema

    input_data = {
        "label": "destination1",
        "options": {},
        "description": "my destination",
        "active": True,
        "plugin": {"slug": "test-destination"},
    }

    data, errors = DestinationInputSchema().load(input_data)

    assert not errors


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_destination_get(client, token, status):
    assert (
        client.get(
            api.url_for(Destinations, destination_id=1), headers=token
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
def test_destination_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
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
def test_destination_put(client, token, status):
    assert (
        client.put(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
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
def test_destination_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(Destinations, destination_id=1), headers=token
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
def test_destination_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
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
def test_destination_list_post_(client, token, status):
    assert (
        client.post(api.url_for(DestinationsList), data={}, headers=token).status_code
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
def test_destination_list_get(client, token, status):
    assert (
        client.get(api.url_for(DestinationsList), headers=token).status_code == status
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
def test_destination_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(DestinationsList), headers=token).status_code
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
def test_destination_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(DestinationsList), data={}, headers=token).status_code
        == status
    )
