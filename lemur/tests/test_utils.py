import pytest


def test_generate_private_key():
    from lemur.common.utils import generate_private_key

    assert generate_private_key('RSA2048')
    assert generate_private_key('RSA4096')

    with pytest.raises(Exception):
        generate_private_key('ECC')
