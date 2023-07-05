from unittest import mock

import pytest

from lemur.plugins.lemur_openssl.plugin import run_process, get_openssl_version
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


def test_export_certificate_to_pkcs12_legacy(app):
    from lemur.plugins.base import plugins

    p = plugins.get("openssl-export")
    options = [
        {"name": "passphrase", "value": "test1234"},
        {"name": "type", "value": "legacy PKCS12 (.p12)"},
    ]

    with mock.patch('lemur.plugins.lemur_openssl.plugin.run_process', mock.Mock(wraps=run_process)) as mock_run_process:
        p.export(INTERNAL_CERTIFICATE_A_STR, "", INTERNAL_PRIVATE_KEY_A_STR, options)
    assert mock_run_process.call_count == 1
    assert ("-legacy" in mock_run_process.call_args_list[0][0][0] or get_openssl_version() < b'3')
