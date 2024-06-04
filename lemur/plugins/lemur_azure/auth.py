from azure.core.credentials import AccessToken, TokenCredential
from azure.identity import ClientSecretCredential

import hvac
import os


class VaultTokenCredential(TokenCredential):
    def __init__(self, audience, client, mount_point, role_name):
        if not audience:
            self.audience = "https://management.azure.com/"
        else:
            self.audience = audience
        self.client = client
        self.mount_point = mount_point
        self.role_name = role_name

    def __eq__(self, other):
        return (
            self.audience == other.audience
            and self.client == other.client
            and self.mount_point == other.mount_point
            and self.role_name == other.role_name
        )

    def get_token(self, *scopes, claims=None, tenant_id=None, **kwargs):
        payload = {"resource": self.audience}
        data = self.client.adapter.get(
            "/v1/{mount_point}/token/{role_name}".format(
                mount_point=self.mount_point,
                role_name=self.role_name,
            ),
            params=payload,
        )["data"]
        return AccessToken(
            token=data["access_token"],
            expires_on=data["expires_on"],
        )


def get_azure_credential(audience, plugin, options):
    """
    Fetches a credential used for authenticating with the Azure API.
    A new credential will be created if one does not already exist.
    If a credential already exists and is valid, then it will be re-used.
    When an existing credential is determined to be invalid, it will be replaced with a new one.

    :param plugin: source or destination plugin
    :param options: options set for the plugin
    :return: an Azure credential
    """
    tenant = plugin.get_option("azureTenant", options)
    auth_method = plugin.get_option("authenticationMethod", options)

    if auth_method == "hashicorpVault":
        mount_point = plugin.get_option("hashicorpVaultMountPoint", options)
        role_name = plugin.get_option("hashicorpVaultRoleName", options)
        client = hvac.Client(url=os.environ["VAULT_ADDR"])

        plugin.credential = VaultTokenCredential(
            audience=audience,
            client=client,
            mount_point=mount_point,
            role_name=role_name,
        )
        return plugin.credential
    elif auth_method == "azureApp":
        app_id = plugin.get_option("azureAppID", options)
        password = plugin.get_option("azurePassword", options)

        plugin.credential = ClientSecretCredential(
            tenant_id=tenant,
            client_id=app_id,
            client_secret=password,
        )
        return plugin.credential

    raise Exception("No supported way to authenticate with Azure")
