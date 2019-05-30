import pytest
from lemur.tests.vectors import INTERNAL_PRIVATE_KEY_A_STR, INTERNAL_CERTIFICATE_A_STR


def test_export_certificate_to_pkcs12(app):
    from lemur.plugins.base import plugins

    p = plugins.get("openssl-export")
    options = [
        {"name": "passphrase", "value": "test1234"},
        {"name": "type", "value": "PKCS12 (.p12)"},
    ]
    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    raw = p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)
    assert raw != b""
