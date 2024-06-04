import os
import unittest
from unittest.mock import patch
from azure.core.credentials import AccessToken
from lemur.plugins.lemur_azure.auth import VaultTokenCredential, get_azure_credential
from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin
from flask import Flask


class TestAzureAuth(unittest.TestCase):
    def setUp(self):
        _app = Flask("lemur_test_azure_auth")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("hvac.Client")
    def test_get_azure_credential(self, hvac_client_mock):
        client = hvac_client_mock()
        client.adapter.get.return_value = {
            "request_id": "f7dcd09c-dde9-fa0d-e98e-e4f238dfe66e",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": {
                "access_token": "faketoken123",
                "expires_in": 14399,
                "expires_on": 1717182214,
                "not_before": 1717167514,
                "refresh_token": "",
                "resource": "https://vault.azure.net/",
                "token_type": "Bearer",
            },
            "wrap_info": None,
            "warnings": None,
            "auth": None,
        }
        plugin = AzureDestinationPlugin()
        options = [
            {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
            {"name": "azureTenant", "value": "mockedTenant"},
            {"name": "authenticationMethod", "value": "hashicorpVault"},
            {"name": "hashicorpVaultRoleName", "value": "mockedRole"},
            {"name": "hashicorpVaultMountPoint", "value": "azure"},
        ]
        cred = get_azure_credential(
            audience="https://management.azure.com", plugin=plugin, options=options
        )
        assert cred == VaultTokenCredential(
            audience="https://management.azure.com",
            client=client,
            mount_point="azure",
            role_name="mockedRole",
        )
        access_token = cred.get_token()
        client.adapter.get.assert_called_with(
            "/v1/azure/token/mockedRole",
            params={"resource": "https://management.azure.com"},
        )
        assert access_token == AccessToken(
            token="faketoken123",
            expires_on=1717182214,
        )
