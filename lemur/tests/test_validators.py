import pytest
from datetime import datetime
from .vectors import PRIVATE_KEY_STR
from marshmallow.exceptions import ValidationError


def test_private_key(session):
    from lemur.common.validators import private_key

    private_key(PRIVATE_KEY_STR)
    private_key(PRIVATE_KEY_STR.decode('utf-8'))

    with pytest.raises(ValidationError):
        private_key('invalid_private_key')


def test_sub_alt_type(session):
    from lemur.common.validators import sub_alt_type

    with pytest.raises(ValidationError):
        sub_alt_type('CNAME')


def test_dates(session):
    from lemur.common.validators import dates

    dates(dict(validity_start=datetime(2016, 1, 1), validity_end=datetime(2016, 1, 5)))

    with pytest.raises(ValidationError):
        dates(dict(validity_start=datetime(2016, 1, 1)))

    with pytest.raises(ValidationError):
        dates(dict(validity_end=datetime(2016, 1, 1)))

    with pytest.raises(ValidationError):
        dates(dict(validity_start=datetime(2016, 1, 5), validity_end=datetime(2016, 1, 1)))

    with pytest.raises(ValidationError):
        dates(dict(validity_start=datetime(2016, 1, 1), validity_end=datetime(2016, 1, 10)))
