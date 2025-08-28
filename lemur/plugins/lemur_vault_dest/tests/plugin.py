from validators.url import url
from lemur.plugins.bases import SourcePlugin
import pytest
from marshmallow import ValidationError

from lemur.plugins.lemur_vault_dest.plugin import VaultSourcePlugin, VaultDestinationPlugin


class TestSourcePlugin(SourcePlugin):
    title = "Test"
    slug = "test-source"
    description = "Enables testing"

    author = "Test"
    author_url = "https://github.com/netflix/lemur.git"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": url,
            "helpMessage": "Valid URL to Hashi Vault instance",
        },
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_certificates(self):
        return

    def update_endpoint(self, endpoint, certificate):
        return


def test_plugin_input_schema_invalid_url_validator(vault_source_plugin):
    from lemur.schemas import PluginInputSchema

    input_data = {
        "description": "Enables testing",
        "slug": "test-source",
        "title": "Test",
        "plugin_options": [
            {
                "name": "vaultUrl",
                "value": "https://vault.example.com",
            },
        ],
    }

    with pytest.raises((TypeError, ValidationError)):
        PluginInputSchema().load(input_data)


def test_vault_plugin_input_schema(session):
    from lemur.schemas import PluginInputSchema

    input_data = {
        "description": "Discovers all certificates in a given path",
        "slug": "vault-source",
        "title": "Test",
        "plugin_options": [
            {
                "name": "vaultUrl",
                "value": "https://vault.example.com",
            },
            {
                "name": "vaultKvApiVersion",
                "value": "2",
            },
            {
                "name": "authenticationMethod",
                "value": "token",
            },
            {
                "name": "tokenFileOrVaultRole",
                "value": "/path/file",
            },
            {
                "name": "vaultMount",
                "value": "mount",
            },
            {
                "name": "vaultPath",
                "value": "path/",
            },
            {
                "name": "objectName",
                "value": "name",
            },
        ],
    }

    data = PluginInputSchema().load(input_data)
    assert data
    assert "plugin_object" in data


@pytest.mark.parametrize("option, value, valid", [
    ("tokenFileOrVaultRole", "", False),
    ("vaultPath", "", False),
    ("tokenFileOrVaultRole", "/leading/slash", True),
    ("vaultPath", "/leading/slash", False),
    ("tokenFileOrVaultRole", "{CN}/subs", False),
    ("vaultPath", "{CN}/subs", False),
    ("tokenFileOrVaultRole", "/leading/slash", True),
    ("vaultPath", "/leading/slash", False),
    ("tokenFileOrVaultRole", "noslash", True),
    ("vaultPath", "noslash", True),
    ("tokenFileOrVaultRole", "some/random/file.json", True),
    ("vaultPath", "some/random/file.json", True),
])
def test_source_options(option, value, valid):
    plugin = VaultSourcePlugin()
    if valid:
        plugin.validate_option_value(option, value)
    else:
        with pytest.raises(ValueError):
            plugin.validate_option_value(option, value)


@pytest.mark.parametrize("option, value, valid", [
    ("tokenFileOrVaultRole", "", False),
    ("vaultPath", "", False),
    ("tokenFileOrVaultRole", "/leading/slash", True),
    ("vaultPath", "/leading/slash", False),
    ("tokenFileOrVaultRole", "{CN}/subs", False),
    ("vaultPath", "{CN}/subs", True),
    ("tokenFileOrVaultRole", "/leading/slash", True),
    ("vaultPath", "/leading/slash", False),
    ("tokenFileOrVaultRole", "noslash", True),
    ("vaultPath", "noslash", True),
    ("tokenFileOrVaultRole", "some/random/file.json", True),
    ("vaultPath", "some/random/file.json", True),
])
def test_dest_options(option, value, valid):
    plugin = VaultDestinationPlugin()
    if valid:
        plugin.validate_option_value(option, value)
    else:
        with pytest.raises(ValueError):
            plugin.validate_option_value(option, value)
