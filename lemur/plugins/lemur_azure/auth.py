from azure.core.exceptions import ClientAuthenticationError
from azure.identity import ClientSecretCredential, CredentialUnavailableError
from flask import current_app

import hvac
import os

from retrying import retry


class RetryableClientSecretCredential(ClientSecretCredential):
    """Credential that authenticates a principle using a client secret. Each call to
    get_token will be retried continuously until it succeeds or the pre-configured 10-minute
    timeout elapses.
    """

    def __init__(self, tenant_id, client_id, client_secret, **kwargs):
        super().__init__(tenant_id, client_id, client_secret, **kwargs)

    @retry(wait_fixed=1000, stop_max_delay=600000)
    def get_token(self, *scopes, **kwargs):
        return super().get_token(*scopes, **kwargs)


def get_azure_credential(plugin, options):
    """
    Fetches a credential used for authenticating with the Azure API.
    A new credential will be created if one does not already exist.
    If a credential already exists and is valid, then it will be re-used.
    When an existing credential is determined to be invalid, it will be replaced with a new one.

    :param plugin: source or destination plugin
    :param options: options set for the plugin
    :return: an Azure credential
    """
    if plugin.credential:
        try:
            plugin.credential.get_token(
                "https://management.azure.com/.default"
            )  # Try to dispense a valid token.
            return plugin.credential
        except (CredentialUnavailableError, ClientAuthenticationError) as e:
            current_app.logger.warning(
                f"Failed to re-use existing Azure credential, another one will attempt to "
                f"be re-generated: {e}"
            )

    tenant = plugin.get_option("azureTenant", options)
    auth_method = plugin.get_option("authenticationMethod", options)

    if auth_method == "hashicorpVault":
        mount_point = plugin.get_option("hashicorpVaultMountPoint", options)
        role_name = plugin.get_option("hashicorpVaultRoleName", options)
        client_id, client_secret = get_oauth_credentials_from_hashicorp_vault(
            mount_point, role_name
        )

        # It may take up-to 10 minutes for the generated OAuth credentials to become usable due
        # to AD replication delay. To account for this, the credential will continuously
        # retry generating an access token until it succeeds or 10 minutes elapse.
        plugin.credential = RetryableClientSecretCredential(
            tenant_id=tenant,
            client_id=client_id,
            client_secret=client_secret,
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


def get_oauth_credentials_from_hashicorp_vault(mount_point, role_name):
    """
    Retrieves OAuth credentials from Hashicorp Vault's Azure secrets engine.

    :param mount_point: Path the Azure secrets engine is mounted on
    :param role_name: Name of the role to fetch credentials for
    :returns:
        - client_id - OAuth client ID
        - client_secret - OAuth client secret
    """
    client = hvac.Client(url=os.environ["VAULT_ADDR"])
    creds = client.secrets.azure.generate_credentials(
        mount_point=mount_point,
        name=role_name,
    )
    return creds["client_id"], creds["client_secret"]
