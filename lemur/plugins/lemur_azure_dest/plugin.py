"""
.. module: lemur.plugins.lemur_azure_dest.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to azure key-vault
     that can be pulled down by end point nodes.

.. moduleauthor:: sirferl
"""
from flask import current_app

from lemur.common.defaults import common_name, bitstrength
from lemur.common.utils import parse_certificate, parse_private_key, check_validation
from lemur.plugins.bases import DestinationPlugin

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import requests
import json
import sys
import base64


def handle_response(my_response):
    """
    Helper function for parsing responses from the Entrust API.
    :param my_response:
    :return: :raise Exception:
    """
    msg = {
        200: "The request was successful.",
        400: "Keyvault Error"
    }

    try:
        data = json.loads(my_response.content)
    except ValueError:
        # catch an empty jason object here
        data = {'response': 'No detailed message'}
    status_code = my_response.status_code
    if status_code > 399:
        raise Exception(f"AZURE error: {msg.get(status_code, status_code)}\n{data}")

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Response",
        "status": status_code,
        "response": data
    }
    current_app.logger.info(log_data)
    if data == {'response': 'No detailed message'}:
        # status if no data
        return status_code
    else:
        #  return data from the response
        return data


def get_access_token(tenant, appID, password, self):
    """
    Gets the access token with the appid and the password and returns it

    Improvment option: we can try to save it and renew it only when necessary

    :param tenant: Tenant used
    :param appID: Application ID from Azure
    :param password: password for Application ID
    :return: Access token to post to the keyvault
    """
    # prepare the call for the access_token
    auth_url = f"https://login.microsoftonline.com/{tenant}/oauth2/token"
    post_data = {
        'grant_type': 'client_credentials',
        'client_id': appID,
        'client_secret': password,
        'resource': 'https://vault.azure.net'
    }
    try:
        response = self.session.post(auth_url, data=post_data)
    except requests.exceptions.RequestException as e:
        current_app.logger.exception(f"AZURE: Error for POST {e}")

    access_token = json.loads(response.content)["access_token"]
    return access_token


class AzureDestinationPlugin(DestinationPlugin):
    """Azure Keyvault Destination plugin for Lemur"""

    title = "Azure"
    slug = "azure-keyvault-destination"
    description = "Allow the uploading of certificates to Azure key vault"

    author = "Sirferl"
    author_url = "https://github.com/sirferl/lemur"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": check_validation("^https?://[a-zA-Z0-9.:-]+$"),
            "helpMessage": "Valid URL to Azure key vault instance",
        },
        {
            "name": "azureTenant",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9/-/?])+$"),
            "helpMessage": "Tenant for the Azure Key Vault",
        },
        {
            "name": "appID",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9/-/?])+$"),
            "helpMessage": "AppID for the Azure Key Vault",
        },
        {
            "name": "azurePassword",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9a-zA-Z.:_~-]+"),
            "helpMessage": "Tenant password for the Azure Key Vault",
        }
    ]

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        super().__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """

        # we use the common name to identify the certificate
        # Azure does not allow "." in the certificate name we replace them with "-"
        cert = parse_certificate(body)
        ca_certs = parse_certificate(cert_chain)
        certificate_name = common_name(cert).replace(".", "-")

        vault_URI = self.get_option("vaultUrl", options)
        tenant = self.get_option("azureTenant", options)
        app_id = self.get_option("appID", options)
        password = self.get_option("azurePassword", options)

        access_token = get_access_token(tenant, app_id, password, self)

        cert_url = f"{vault_URI}/certificates/{certificate_name}/import?api-version=7.1"
        post_header = {
            "Authorization": f"Bearer {access_token}"
        }
        # Azure keyvault accepts PEM and PKCS12-Format Certificates
        # only the latter is usable for Azure Application Gateway
        # therefore we upload in PKCS12 format
        cert_p12 = pkcs12.serialize_key_and_certificates(
            name=certificate_name.encode(),
            key=parse_private_key(private_key),
            cert=cert,
            cas=[ca_certs],
            encryption_algorithm=serialization.NoEncryption()
        )
        # encode the p12 string with b64 and encode is at utf-8 again to get string for JSON
        post_body = {
            "value": base64.b64encode(cert_p12).decode('utf-8'),
            "policy": {
                "key_props": {
                    "exportable": True,
                    "kty": "RSA",
                    "key_size": bitstrength(cert),
                    "reuse_key": True
                },
                "secret_props": {
                    "contentType": "application/x-pkcs12"
                }
            }
        }

        try:
            response = self.session.post(cert_url, headers=post_header, json=post_body)
            return_value = handle_response(response)
        except requests.exceptions.RequestException as e:
            current_app.logger.exception(f"AZURE: Error for POST {e}")
