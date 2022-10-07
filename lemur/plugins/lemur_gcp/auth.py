import hvac
import os

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials


def get_gcp_credentials(plugin, options):
    if plugin.get_option('authenticationMethod', options) == "vault":
        # make a request to vault for GCP token
        return get_gcp_credentials_from_vault(plugin, options)
    elif plugin.get_option('authenticationMethod', options) == "serviceAccountToken":
        if plugin.get_option('serviceAccountTokenPath', options) is not None:
            return service_account.Credentials.from_service_account_file(
                plugin.get_option('serviceAccountTokenPath', options)
            )
    raise Exception("No supported way to authenticate with GCP")


def get_gcp_credentials_from_vault(plugin, options):
    service_token = hvac.Client(os.environ['VAULT_ADDR']) \
        .secrets.gcp \
        .generate_oauth2_access_token(
        roleset="",
        mount_point=f"{plugin.get_option('vaultMountPoint', options)}"
    )["data"]["token"].rstrip(".")

    credentials = Credentials(service_token)

    return credentials
