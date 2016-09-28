import pytest
import six

from lemur.tests.vectors import INTERNAL_CERTIFICATE_A_STR, INTERNAL_PRIVATE_KEY_A_STR


def test_export_truststore(app):
    from lemur.plugins.base import plugins

    p = plugins.get('java-truststore-jks')
    options = [{'name': 'passphrase', 'value': 'test1234'}]
    actual = p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    assert actual[0] == 'jks'
    assert actual[1] == 'test1234'
    assert isinstance(actual[2], bytes)


def test_export_truststore_default_password(app):
    from lemur.plugins.base import plugins

    p = plugins.get('java-truststore-jks')
    options = []
    actual = p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    assert actual[0] == 'jks'
    assert isinstance(actual[1], str)
    assert isinstance(actual[2], bytes)


def test_export_keystore(app):
    from lemur.plugins.base import plugins

    p = plugins.get('java-keystore-jks')
    options = [{'name': 'passphrase', 'value': 'test1234'}]

    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    actual = p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)

    assert actual[0] == 'jks'
    assert actual[1] == 'test1234'
    assert isinstance(actual[2], bytes)


def test_export_keystore_default_password(app):
    from lemur.plugins.base import plugins

    p = plugins.get('java-keystore-jks')
    options = []

    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    actual = p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)

    assert actual[0] == 'jks'
    assert isinstance(actual[1], six.string_types)
    assert isinstance(actual[2], bytes)
