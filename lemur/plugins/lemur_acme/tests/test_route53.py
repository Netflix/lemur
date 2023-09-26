from unittest.mock import MagicMock

import pytest

from lemur.plugins.lemur_acme.route53 import _find_zone_id
from lemur.tests.conftest import app  # noqa


def test_zone_selection(app):  # noqa
    # Mocking AWS client
    client = MagicMock()

    zones = [
        {"Config": {"PrivateZone": False}, "Name": "acme.identity.uq.edu.au.", "Id": "Z1"},
        {"Config": {"PrivateZone": False}, "Name": "dev.acme.identity.uq.edu.au.", "Id": "Z2"},
        {"Config": {"PrivateZone": True}, "Name": "test.dev.acme.identity.uq.edu.au.", "Id": "Z3"}
    ]

    # Mocking the paginator
    paginator = MagicMock()
    paginator.paginate.return_value = [{"HostedZones": zones}]
    client.get_paginator.return_value = paginator

    # Replace this with reference to your function
    assert _find_zone_id("test.dev.acme.identity.uq.edu.au", client) == "Z2"
    assert _find_zone_id("another.dev.acme.identity.uq.edu.au", client) == "Z2"
    assert _find_zone_id("test2.acme.identity.uq.edu.au", client) == "Z1"

    # Test that it raises a ValueError for a domain where no matching zone is found
    with pytest.raises(ValueError):
        _find_zone_id("test3.some.other.domain", client)
