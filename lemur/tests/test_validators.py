from marshmallow.exceptions import ValidationError
from .vectors import PRIVATE_KEY_STR


def test_private_key():
    from lemur.common.validators import private_key
    try:
        private_key(PRIVATE_KEY_STR)
        assert True
    except ValidationError:
        assert False, "failed to validate private key as a bytes object"


def test_private_key_str_object():
    from lemur.common.validators import private_key
    try:
        private_key(PRIVATE_KEY_STR.decode('utf-8'))
        assert True
    except ValidationError:
        assert False, "failed to validate private key as a str object"


def test_private_key_invalid():
    from lemur.common.validators import private_key
    try:
        private_key('invalid_private_key')
        assert False, "invalid private key should have raised an exception"
    except ValidationError:
        assert True
