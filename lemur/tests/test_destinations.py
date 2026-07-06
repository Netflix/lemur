import json

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


# --- GHSA-6c8m-q6g9-vrw3: sensitive option redaction ---

class FakePlugin:
    slug = "sftp-destination"
    title = "SFTP"
    description = "SFTP destination"
    options: list = []
    id = 1
    label = None
    active = None


def make_fake_destination():
    """Build a fresh destination each call; fill_object mutates option dicts in place."""

    class FakeDestination:
        id = 1
        label = "prod-sftp"
        description = "test"
        active = True
        options = [
            {"name": "host", "type": "str", "value": "10.0.5.20"},
            {"name": "user", "type": "str", "value": "deploy"},
            {"name": "password", "type": "str", "value": "S3cr3t!", "sensitive": True},
            {"name": "privateKeyPass", "type": "str", "value": "key-pass", "sensitive": True},
        ]
        plugin = FakePlugin()

    return FakeDestination()


def test_destination_output_schema_redacts_sensitive_options_for_non_admin(logged_in_user):
    """Non-admins must not see sensitive option values in serialized output."""
    from lemur.destinations.schemas import DestinationOutputSchema

    result = DestinationOutputSchema().dump(make_fake_destination()).data
    serialized = json.dumps(result)

    assert "S3cr3t!" not in serialized
    assert "key-pass" not in serialized

    options_by_name = {o["name"]: o for o in result["options"]}
    assert options_by_name["password"]["value"] is None
    assert options_by_name["privateKeyPass"]["value"] is None
    assert options_by_name["host"]["value"] == "10.0.5.20"


def test_destination_output_schema_preserves_sensitive_options_for_admin(logged_in_admin):
    """Admins must still be able to retrieve sensitive option values."""
    from lemur.destinations.schemas import DestinationOutputSchema

    result = DestinationOutputSchema().dump(make_fake_destination()).data
    options_by_name = {o["name"]: o for o in result["options"]}
    assert options_by_name["password"]["value"] == "S3cr3t!"
    assert options_by_name["privateKeyPass"]["value"] == "key-pass"


def test_destination_output_schema_preserves_non_sensitive_options(logged_in_user):
    """Non-sensitive option values must be preserved in serialized output."""
    from lemur.destinations.schemas import DestinationOutputSchema

    class FakePlugin:
        slug = "aws-destination"
        title = "AWS"
        description = "AWS destination"
        options = []
        id = 1
        label = None
        active = None

    class FakeDestination:
        id = 2
        label = "prod-aws"
        description = "test"
        active = True
        options = [
            {"name": "accountNumber", "type": "str", "value": "123456789012"},
        ]
        plugin = FakePlugin()

    result = DestinationOutputSchema().dump(FakeDestination()).data
    options_by_name = {o["name"]: o for o in result["options"]}
    assert options_by_name["accountNumber"]["value"] == "123456789012"
