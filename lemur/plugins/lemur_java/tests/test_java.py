import pytest
from lemur.tests.vectors import INTERNAL_CERTIFICATE_A_STR, INTERNAL_PRIVATE_KEY_A_STR


def test_export_certificate_to_jks(app):
    from lemur.plugins.base import plugins
    p = plugins.get('java-truststore-jks')
    options = [{'name': 'passphrase', 'value': 'test1234'}]
    raw = p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)
    assert raw != b""


def test_export_keystore(app):
    from lemur.plugins.base import plugins
    p = plugins.get('java-keystore-jks')
    options = [{'name': 'passphrase', 'value': 'test1234'}]
    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    raw = p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)
    assert raw != b""
