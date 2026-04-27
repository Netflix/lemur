from datetime import datetime

import pytest
from marshmallow.exceptions import ValidationError

from lemur.common.utils import parse_private_key
from lemur.common.validators import verify_private_key_match
from lemur.tests.vectors import INTERMEDIATE_CERT, SAN_CERT, SAN_CERT_KEY


def test_private_key(session):
    parse_private_key(SAN_CERT_KEY)

    with pytest.raises(ValueError):
        parse_private_key("invalid_private_key")


def test_parse_ec_private_key_with_parameters(session):
    """Verify that EC keys with an EC PARAMETERS prefix can be parsed (issue #5058)."""
    import subprocess
    result = subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "secp384r1"],
        capture_output=True, text=True,
    )
    ec_key_with_params = result.stdout
    assert "BEGIN EC PARAMETERS" in ec_key_with_params
    key = parse_private_key(ec_key_with_params)
    assert key is not None


def test_validate_private_key(session):
    key = parse_private_key(SAN_CERT_KEY)

    verify_private_key_match(key, SAN_CERT)

    with pytest.raises(ValidationError):
        # Wrong key for certificate
        verify_private_key_match(key, INTERMEDIATE_CERT)


def test_sub_alt_type(session):
    from lemur.common.validators import sub_alt_type

    with pytest.raises(ValidationError):
        sub_alt_type("CNAME")


def test_dates(session):
    from lemur.common.validators import dates

    dates(dict(validity_start=datetime(2016, 1, 1), validity_end=datetime(2016, 1, 5)))

    with pytest.raises(ValidationError):
        dates(dict(validity_start=datetime(2016, 1, 1)))

    with pytest.raises(ValidationError):
        dates(dict(validity_end=datetime(2016, 1, 1)))

    with pytest.raises(ValidationError):
        dates(
            dict(validity_start=datetime(2016, 1, 5), validity_end=datetime(2016, 1, 1))
        )

    with pytest.raises(ValidationError):
        dates(
            dict(
                validity_start=datetime(2016, 1, 1), validity_end=datetime(2016, 1, 10)
            )
        )
