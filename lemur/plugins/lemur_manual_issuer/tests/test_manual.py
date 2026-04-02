import pytest
from flask import Flask
from lemur.plugins.lemur_manual_issuer import plugin

def test_allows_auto_resolve_property():
    p = plugin.ManualIssuerPlugin()
    assert p.allows_auto_resolve is False

def test_create_certificate_returns_pending():
    p = plugin.ManualIssuerPlugin()
    app = Flask('test')
    with app.app_context():
        cert, chain, external_id = p.create_certificate(None, {})
        assert cert == ""
        assert chain == ""
        assert isinstance(external_id, int)

def test_create_authority_returns_expected_roles():
    app = Flask('test')
    with app.app_context():
        options = {
            "name": "test",
            "plugin": {
                "plugin_options": [
                    {"name": "public_certificate", "value": "-----BEGIN CERTIFICATE-----FAKE"}
                ]
            }
        }
        pub, chain, key, roles = plugin.ManualIssuerPlugin.create_authority(options)
        assert pub.startswith("-----BEGIN CERTIFICATE-----")
        assert chain is None
        assert key is None
        assert roles[0]["name"] == "test_admin"
        assert roles[1]["name"] == "test_operator"

def test_get_plugin_options_valid():
    options = {"plugin": {"plugin_options": [1, 2, 3]}}
    result = plugin.get_plugin_options(options)
    assert result == [1, 2, 3]

def test_get_plugin_options_invalid():
    options = {"plugin": {}}
    app = Flask('test')
    with app.app_context():
        with pytest.raises(plugin.InvalidConfiguration):
            plugin.get_plugin_options(options)

def test_get_option_pub_cert():
    opts = [
        {"name": "public_certificate", "value": "CERTDATA"},
        {"name": "other", "value": "X"}
    ]
    result = plugin.get_option_pub_cert(opts)
    assert result == "CERTDATA"


def test_get_option_pub_cert_none():
    opts = []
    result = plugin.get_option_pub_cert(opts)
    assert result is None