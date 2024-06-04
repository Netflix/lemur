"""
.. module: lemur.plugins.lemur_azure.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to azure key-vault
     that can be pulled down by end point nodes.

.. moduleauthor:: sirferl
"""
from flask import current_app
from sentry_sdk import capture_exception
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.cdn.models import UserManagedHttpsParameters
from azure.mgmt.network.models import (
    ApplicationGatewaySslPolicyName,
    ApplicationGatewaySslPolicyType,
    ApplicationGatewaySslCipherSuite,
)

from lemur.common.defaults import common_name, bitstrength
from lemur.common.utils import (
    parse_certificate,
    parse_private_key,
    check_validation,
    get_key_type_from_certificate,
)
from lemur.extensions import metrics
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_azure.auth import get_azure_credential

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def get_cdn_endpoints(cdn_client):
    endpoints = []
    for profile in cdn_client.profiles.list():
        resource_group_name = resource_group_from_id(profile.id)
        for endpoint in cdn_client.endpoints.list_by_profile(
            resource_group_name=resource_group_name, profile_name=profile.name
        ):
            ep = dict(
                name=endpoint.name,
                dnsname=endpoint.host_name,
                port=443,  # Azure CDN doesn't support configuring a custom port.
                type="azurecdn",
                sni_certificates=[],
                policy=dict(
                    name="none",  # Azure CDN doesn't support configuring SSL policies.
                    ciphers=[],
                ),
            )
            for domain in cdn_client.custom_domains.list_by_endpoint(
                resource_group_name=resource_group_name,
                profile_name=profile.name,
                endpoint_name=endpoint.name,
            ):
                if isinstance(
                    domain.custom_https_parameters, UserManagedHttpsParameters
                ):
                    ep["sni_certificates"].append(
                        dict(
                            name=domain.custom_https_parameters.certificate_source_parameters.secret_name,
                            path="",
                            registry_type="keyvault",
                        )
                    )
                    endpoints.append(ep)
    return endpoints


def get_application_gateways(network_client):
    endpoints = []
    for appgw in network_client.application_gateways.list_all():
        for listener in appgw.http_listeners:
            if listener.protocol == "Https":
                port = port_from_id(appgw, listener.frontend_port.id)
                ip_address, is_public = ip_from_cfg_id(
                    appgw, network_client, listener.frontend_ip_configuration.id
                )
                listener_type = "public" if is_public else "internal"
                ep = dict(
                    name=f"{appgw.name}-{listener_type}-{port}",
                    dnsname=ip_address,
                    port=port,
                    type="applicationgateway",
                    primary_certificate=certificate_from_id(
                        appgw, listener.ssl_certificate.id
                    ),
                    sni_certificates=[],
                    policy=policy_from_appgw(network_client, appgw),
                )
                endpoints.append(ep)
    return endpoints


def get_and_decode_certificate(certificate_client, certificate_name):
    crt = certificate_client.get_certificate(certificate_name=certificate_name)
    decoded_crt = x509.load_der_x509_certificate(bytes(crt.cer))
    return dict(
        body=decoded_crt.public_bytes(encoding=serialization.Encoding.PEM).decode(
            "utf-8"
        ),
        name=crt.name,
    )


def parse_ca_vendor(chain):
    org_name = chain.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[
        0
    ].value.strip()
    if "DigiCert" in org_name:
        return "DigiCert"
    elif "Sectigo" in org_name:
        return "Sectigo"
    return org_name.replace(" ", "").strip()


def policy_from_appgw(network_client, appgw):
    if not appgw.ssl_policy:
        return dict(
            name="none",
            ciphers=[],
        )
    policy = dict(
        name="",
        ciphers=[],
    )
    policy_name = appgw.ssl_policy.policy_name
    if isinstance(appgw.ssl_policy.policy_name, ApplicationGatewaySslPolicyName):
        policy_name = appgw.ssl_policy.policy_name.value
    policy_type = appgw.ssl_policy.policy_type
    if isinstance(appgw.ssl_policy.policy_type, ApplicationGatewaySslPolicyType):
        policy_type = appgw.ssl_policy.policy_type.value

    cipher_suites = []
    if policy_type == "Predefined":
        predefined_policy = (
            network_client.application_gateways.get_ssl_predefined_policy(
                predefined_policy_name=policy_name
            )
        )
        cipher_suites = predefined_policy.cipher_suites
    elif appgw.ssl_policy.cipher_suites:
        cipher_suites = appgw.ssl_policy.cipher_suites

    for c in cipher_suites:
        if isinstance(c, ApplicationGatewaySslCipherSuite):
            policy["ciphers"].append(c.value)
        else:
            policy["ciphers"].append(c)
    policy["name"] = policy_name

    return policy


def certificate_from_id(appgw, certificate_id):
    for cert in appgw.ssl_certificates:
        if cert.id == certificate_id:
            return dict(
                name=cert.name,
                path="",
                registry_type="keyvault",
            )
    raise Exception(
        f"No certificate with ID {certificate_id} associated with {appgw.id}"
    )


def port_from_id(appgw, port_id):
    for fp in appgw.frontend_ports:
        if fp.id == port_id:
            return fp.port
    raise Exception(f"No port with ID {port_id} associated with {appgw.id}")


def resource_group_from_id(resource_id):
    return resource_id.lstrip("/").split("/")[3]


def resource_name_from_id(resource_id):
    return resource_id.lstrip("/").split("/")[7]


def ip_from_cfg_id(appgw, network_client, frontend_ip_cfg_id):
    for cfg in appgw.frontend_ip_configurations:
        if cfg.id == frontend_ip_cfg_id:
            if cfg.public_ip_address:
                resource_group = resource_group_from_id(cfg.public_ip_address.id)
                ip_name = resource_name_from_id(cfg.public_ip_address.id)
                return (
                    network_client.public_ip_addresses.get(
                        resource_group_name=resource_group,
                        public_ip_address_name=ip_name,
                    ).ip_address,
                    True,
                )
            elif cfg.private_ip_address:
                return cfg.private_ip_address, False
    raise Exception(
        f"No IP address associated with {appgw.id} and frontend IP configuration {frontend_ip_cfg_id}"
    )


class AzureDestinationPlugin(DestinationPlugin):
    """Azure Keyvault Destination plugin for Lemur"""

    title = "Azure"
    slug = "azure-keyvault-destination"
    description = "Allow the uploading of certificates to Azure key vault"

    author = "Sirferl"
    author_url = "https://github.com/sirferl/lemur"

    options = [
        {
            "name": "azureKeyVaultUrl",
            "type": "str",
            "required": True,
            "validation": check_validation("^https?://[a-zA-Z0-9.:-]+$"),
            "helpMessage": "Valid URL to Azure key vault instance",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "azureApp",
            "required": True,
            "available": ["hashicorpVault", "azureApp"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "azureTenant",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9-?])+$"),
            "helpMessage": "Tenant for the Azure Key Vault.",
        },
        {
            "name": "azureAppID",
            "type": "str",
            "required": False,
            "validation": check_validation("^([a-zA-Z0-9-?]?)+$"),
            "helpMessage": "AppID for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "azurePassword",
            "type": "str",
            "required": False,
            "validation": check_validation("([0-9a-zA-Z.:_-~]?)+"),
            "helpMessage": "Tenant password for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "hashicorpVaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path the Azure secrets engine was mounted on. Required if authentication "
            "method is 'hashicorpVault'.",
        },
        {
            "name": "hashicorpVaultRoleName",
            "type": "str",
            "required": False,
            "helpMessage": "Name of the role to fetch credentials for. Required if authentication "
            "method is 'hashicorpVault'.",
        },
    ]

    def __init__(self, *args, **kwargs):
        self.credential = None
        super(AzureDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """

        # The certificate name must be a 1-127 character string, starting with a letter
        # and containing only 0-9, a-z, A-Z, and -.
        cert = parse_certificate(body)
        ca_certs = parse_certificate(cert_chain)
        ca_vendor = parse_ca_vendor(ca_certs)
        key_type = get_key_type_from_certificate(body)
        certificate_name = "{common_name}-{ca_vendor}-{key_type}".format(
            common_name=common_name(cert).replace(".", "-").replace("*", "star"),
            ca_vendor=ca_vendor,
            key_type=key_type,
        )

        certificate_client = CertificateClient(
            credential=get_azure_credential(
                audience="https://vault.azure.net", plugin=self, options=options
            ),
            vault_url=self.get_option("azureKeyVaultUrl", options),
        )
        certificate_client.import_certificate(
            certificate_name=certificate_name,
            certificate_bytes=pkcs12.serialize_key_and_certificates(
                name=certificate_name.encode(),
                key=parse_private_key(private_key),
                cert=cert,
                cas=[ca_certs],
                encryption_algorithm=serialization.NoEncryption(),
            ),
            enabled=True,
            policy=CertificatePolicy(
                exportable=True,
                key_type="RSA",
                key_size=bitstrength(cert),
                reuse_key=True,
                content_type="application/x-pkcs12",
            ),
            tags={"lemur.managed": "true"},
        )


class AzureSourcePlugin(SourcePlugin):
    title = "Azure"
    slug = "azure-source"
    description = (
        "Discovers all certificates and Application Gateways within an Azure tenant"
    )

    author = "Bob Shannon"
    author_url = "https://github.com/datadog/lemur"

    options = [
        {
            "name": "azureKeyVaultUrl",
            "type": "str",
            "required": True,
            "validation": check_validation("^https?://[a-zA-Z0-9.:-]+$"),
            "helpMessage": "Azure key vault to discover certificates from.",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "azureApp",
            "required": True,
            "available": ["hashicorpVault", "azureApp"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "azureTenant",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9-?])+$"),
            "helpMessage": "Tenant to discover Azure resources from.",
        },
        {
            "name": "azureAppID",
            "type": "str",
            "required": False,
            "validation": check_validation("^([a-zA-Z0-9-?]?)+$"),
            "helpMessage": "AppID for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "azurePassword",
            "type": "str",
            "required": False,
            "validation": check_validation("([0-9a-zA-Z.:_-~]?)+"),
            "helpMessage": "Tenant password for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "hashicorpVaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path the Azure secrets engine was mounted on. Required if authentication "
            "method is 'hashicorpVault'.",
        },
        {
            "name": "hashicorpVaultRoleName",
            "type": "str",
            "required": False,
            "helpMessage": "Name of the role to fetch credentials for. Required if authentication "
            "method is 'hashicorpVault'.",
        },
    ]

    def __init__(self, *args, **kwargs):
        self.credential = None
        super(AzureSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        certificates = []
        certificate_client = CertificateClient(
            credential=get_azure_credential(
                audience="https://vault.azure.net", plugin=self, options=options
            ),
            vault_url=self.get_option("azureKeyVaultUrl", options),
        )
        for prop in certificate_client.list_properties_of_certificates():
            try:
                certificates.append(
                    get_and_decode_certificate(
                        certificate_client=certificate_client,
                        certificate_name=prop.name,
                    )
                )
            except HttpResponseError:
                current_app.logger.warning(
                    f"get_azure_key_vault_certificate_failed: Unable to get certificate for {prop.name}"
                )
                capture_exception()
                metrics.send(
                    "get_azure_key_vault_certificate_failed",
                    "counter",
                    1,
                    metric_tags={
                        "certificate_name": prop.name,
                        "tenant": self.get_option("azureTenant", options),
                    },
                )
        return certificates

    def get_certificate_by_name(self, certificate_name, options):
        certificate_client = CertificateClient(
            credential=get_azure_credential(
                audience="https://vault.azure.net", plugin=self, options=options
            ),
            vault_url=self.get_option("azureKeyVaultUrl", options),
        )
        try:
            return get_and_decode_certificate(
                certificate_client=certificate_client, certificate_name=certificate_name
            )
        except ResourceNotFoundError:
            return None

    def get_endpoints(self, options, **kwargs):
        credential = get_azure_credential(
            audience="https://management.azure.com", plugin=self, options=options
        )
        endpoints = []
        for subscription in SubscriptionClient(
            credential=credential
        ).subscriptions.list():
            network_client = NetworkManagementClient(
                credential=credential, subscription_id=subscription.subscription_id
            )
            endpoints += get_application_gateways(network_client)

            cdn_client = CdnManagementClient(
                credential=credential, subscription_id=subscription.subscription_id
            )
            endpoints += get_cdn_endpoints(cdn_client)
        return endpoints

    @staticmethod
    def update_endpoint(endpoint, certificate):
        current_app.logger.info(
            {
                "message": "No explicit action required to rotate endpoint. Azure will automatically perform the rotation "
                "after the new certificate is uploaded to its Key Vault.",
                "endpoint": endpoint.name,
                "certificate": certificate.name,
            }
        )
        return

    @staticmethod
    def replace_sni_certificate(endpoint, old_cert, new_cert):
        current_app.logger.info(
            {
                "message": "No explicit action required to rotate endpoint. Azure will automatically perform the rotation "
                "after the new certificate is uploaded to its Key Vault.",
                "endpoint": endpoint.name,
                "old_certificate": old_cert.name,
                "new_certificate": new_cert.name,
            }
        )
