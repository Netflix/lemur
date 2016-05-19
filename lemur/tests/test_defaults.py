

def test_cert_get_cn(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import common_name

    assert common_name(INTERNAL_VALID_LONG_CERT) == 'long.lived.com'


def test_cert_sub_alt_domains(client):
    from .vectors import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import domains

    assert domains(INTERNAL_VALID_LONG_CERT) == []
    assert domains(INTERNAL_VALID_SAN_CERT) == ['example2.long.com', 'example3.long.com']


def test_cert_is_san(client):
    from .vectors import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import san

    assert not san(INTERNAL_VALID_LONG_CERT)
    assert san(INTERNAL_VALID_SAN_CERT)


def test_cert_is_wildcard(client):
    from .vectors import INTERNAL_VALID_WILDCARD_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import is_wildcard
    assert is_wildcard(INTERNAL_VALID_WILDCARD_CERT)
    assert not is_wildcard(INTERNAL_VALID_LONG_CERT)


def test_cert_bitstrength(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import bitstrength
    assert bitstrength(INTERNAL_VALID_LONG_CERT) == 2048


def test_cert_issuer(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.common.defaults import issuer
    assert issuer(INTERNAL_VALID_LONG_CERT) == 'Example'


def test_create_name(client):
    from lemur.common.defaults import certificate_name
    from datetime import datetime
    assert certificate_name(
        'example.com',
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        False
    ) == 'example.com-ExampleInc-20150507-20150512'
    assert certificate_name(
        'example.com',
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        True
    ) == 'SAN-example.com-ExampleInc-20150507-20150512'
