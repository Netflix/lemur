from unittest.mock import MagicMock

import pytest

from lemur import create_app
from lemur.plugins.lemur_acme.route53 import find_zone_id


def test_zone_selection():
    app = create_app()
    with app.app_context():
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
        assert find_zone_id(client, "test.dev.acme.identity.uq.edu.au") == "Z2"
        assert find_zone_id(client, "another.dev.acme.identity.uq.edu.au") == "Z2"
        assert find_zone_id(client, "test2.acme.identity.uq.edu.au") == "Z1"

        # Test that it raises a ValueError for a domain where no matching zone is found
        with pytest.raises(ValueError):
            find_zone_id(client, "test3.some.other.domain")
