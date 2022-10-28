import os
import unittest
from unittest.mock import patch

from lemur.plugins.lemur_azure import plugin

from azure.mgmt.subscription.models import Subscription
from azure.mgmt.network.models import (
    ApplicationGateway,
    ApplicationGatewayFrontendIPConfiguration,
    ApplicationGatewayFrontendPort,
    ApplicationGatewayHttpListener,
    ApplicationGatewaySslCertificate,
    PublicIPAddress,
    SubResource
)


def _frontend_ip_cfg_resource_id(subscription_id, appgw_name, resource_name):
    return f"/subscriptions/{subscription_id}/resourceGroups/fake-resource-group/providers/Microsoft.Network/applicationGateways/{appgw_name}/frontendIPConfigurations/{resource_name}"


def _public_ip_resource_id(subscription_id, resource_name):
    return f"/subscriptions/{subscription_id}/resourceGroups/fake-resource-group/providers/Microsoft.Network/publicIPAddresses/{resource_name}"


def _frontend_port_id(subscription_id, appgw_name, resource_name):
    return f"/subscriptions/{subscription_id}/resourceGroups/fake-resource-group/providers/Microsoft.Network/applicationGateways/{appgw_name}/frontendPorts/{resource_name}"


def _ssl_certificate_id(subscription_id, appgw_name, resource_name):
    return f"/subscriptions/{subscription_id}/resourceGroups/fake-resource-group/providers/Microsoft.Network/applicationGateways/{appgw_name}/sslCertificates/{resource_name}"


class TestAzureSource(unittest.TestCase):
    def setUp(self):
        self.azure_source = plugin.AzureSourcePlugin()

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.mgmt.network.v2022_05_01.operations.PublicIPAddressesOperations.get")
    @patch("azure.mgmt.network.v2022_05_01.operations.ApplicationGatewaysOperations.list_all")
    @patch("azure.mgmt.subscription.operations.SubscriptionsOperations.list")
    def test_get_endpoints(self, list_subscriptions_mock, list_all_appgw_mock, get_public_ip_mock):
        test_subscription_1 = Subscription()
        test_subscription_1.subscription_id = "fake-subscription-1"
        test_subscription_2 = Subscription()
        test_subscription_2.subscription_id = "fake-subscription-2"

        foo_appgw = ApplicationGateway(
            id="fake-appgw-foo",
            http_listeners=[
                ApplicationGatewayHttpListener(
                    name="public-listener-443",
                    protocol="Https",
                    frontend_ip_configuration=SubResource(
                        id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-1",
                                                        appgw_name="fake-appgw-foo",
                                                        resource_name="fake-frontend-ip-cfg-foo-1")),
                    frontend_port=SubResource(
                        id=_frontend_port_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-foo",
                                             resource_name="fake-frontend-port-foo")),
                    ssl_certificate=SubResource(
                        id=_ssl_certificate_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-foo",
                                               resource_name="fake-ssl-certificate-foo")),
                ),
            ],
            frontend_ip_configurations=[
                ApplicationGatewayFrontendIPConfiguration(
                    id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-1",
                                                    appgw_name="fake-appgw-foo",
                                                    resource_name="fake-frontend-ip-cfg-foo-1"),
                    public_ip_address=SubResource(
                        id=_public_ip_resource_id(subscription_id="fake-subscription-1",
                                                  resource_name="fake-public-ipv4-foo-1"),
                    ),
                ),
            ],
            frontend_ports=[
                ApplicationGatewayFrontendPort(
                    id=_frontend_port_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-foo",
                                         resource_name="fake-frontend-port-foo"),
                    port=443,
                ),
            ],
            ssl_certificates=[
                ApplicationGatewaySslCertificate(
                    id=_ssl_certificate_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-foo",
                                           resource_name="fake-ssl-certificate-foo"),
                    name="fake-ssl-certificate-foo",
                )
            ],
        )
        foo_public_ip = PublicIPAddress(
            id=_public_ip_resource_id(subscription_id="fake-subscription-1", resource_name="fake-public-ipv4-foo-1"),
            ip_address="204.13.0.120",
        )
        foo_appgw.name = "fake-appgw-foo"
        bar_appgw = ApplicationGateway(
            id="fake-appgw-bar-plaintext-only",
            http_listeners=[
                ApplicationGatewayHttpListener(
                    name="public-listener-80",
                    protocol="Http",
                    frontend_ip_configuration=SubResource(
                        id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-1",
                                                        appgw_name="fake-appgw-bar",
                                                        resource_name="fake-frontend-ip-cfg-bar-1")),
                    frontend_port=SubResource(
                        id=_frontend_port_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-bar",
                                             resource_name="fake-frontend-port-bar")),
                )
            ],
            frontend_ip_configurations=[
                ApplicationGatewayFrontendIPConfiguration(
                    id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-1",
                                                    appgw_name="fake-appgw-bar",
                                                    resource_name="fake-frontend-ip-cfg-bar-1"),
                    public_ip_address=SubResource(
                        id=_public_ip_resource_id(subscription_id="fake-subscription-1",
                                                  resource_name="fake-public-ipv4-bar-1"),
                    ),
                ),
            ],
            frontend_ports=[
                ApplicationGatewayFrontendPort(
                    id=_frontend_port_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-bar",
                                         resource_name="fake-frontend-port-bar"),
                    port=443,
                ),
            ],
            ssl_certificates=[
                ApplicationGatewaySslCertificate(
                    id=_ssl_certificate_id(subscription_id="fake-subscription-1", appgw_name="fake-appgw-bar",
                                           resource_name="fake-ssl-certificate-bar"),
                    name="fake-ssl-certificate-bar",
                )
            ],
        )
        bar_appgw.name = "fake-appgw-bar-plaintext-only"
        baz_appgw = ApplicationGateway(
            id="fake-appgw-baz",
            http_listeners=[
                ApplicationGatewayHttpListener(
                    name="public-listener-443",
                    protocol="Https",
                    frontend_ip_configuration=SubResource(
                        id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-2",
                                                        appgw_name="fake-appgw-baz",
                                                        resource_name="fake-frontend-ip-cfg-baz-1")),
                    frontend_port=SubResource(
                        id=_frontend_port_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                             resource_name="fake-frontend-port-baz-1")),
                    ssl_certificate=SubResource(
                        id=_ssl_certificate_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                               resource_name="fake-ssl-certificate-baz-1")),
                ),
                ApplicationGatewayHttpListener(
                    name="internal-listener-443",
                    protocol="Https",
                    frontend_ip_configuration=SubResource(
                        id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-2",
                                                        appgw_name="fake-appgw-baz",
                                                        resource_name="fake-frontend-ip-cfg-baz-2")),
                    frontend_port=SubResource(
                        id=_frontend_port_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                             resource_name="fake-frontend-port-baz-2")),
                    ssl_certificate=SubResource(
                        id=_ssl_certificate_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                               resource_name="fake-ssl-certificate-baz-2")),
                )
            ],
            frontend_ip_configurations=[
                ApplicationGatewayFrontendIPConfiguration(
                    id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-2",
                                                    appgw_name="fake-appgw-baz",
                                                    resource_name="fake-frontend-ip-cfg-baz-1"),
                    public_ip_address=SubResource(
                        id=_public_ip_resource_id(subscription_id="fake-subscription-2",
                                                  resource_name="fake-public-ipv4-baz-1"),
                    ),
                ),
                ApplicationGatewayFrontendIPConfiguration(
                    id=_frontend_ip_cfg_resource_id(subscription_id="fake-subscription-2",
                                                    appgw_name="fake-appgw-baz",
                                                    resource_name="fake-frontend-ip-cfg-baz-2"),
                    private_ip_address="10.10.200.1",
                ),
            ],
            frontend_ports=[
                ApplicationGatewayFrontendPort(
                    id=_frontend_port_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                         resource_name="fake-frontend-port-baz-1"),
                    port=443,
                ),
                ApplicationGatewayFrontendPort(
                    id=_frontend_port_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                         resource_name="fake-frontend-port-baz-2"),
                    port=443,
                ),
            ],
            ssl_certificates=[
                ApplicationGatewaySslCertificate(
                    id=_ssl_certificate_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                           resource_name="fake-ssl-certificate-baz-1"),
                    name="fake-ssl-certificate-baz-1",
                ),
                ApplicationGatewaySslCertificate(
                    id=_ssl_certificate_id(subscription_id="fake-subscription-2", appgw_name="fake-appgw-baz",
                                           resource_name="fake-ssl-certificate-baz-2"),
                    name="fake-ssl-certificate-baz-2",
                )
            ],
        )
        baz_appgw.name = "fake-appgw-baz"
        baz_public_ip = PublicIPAddress(
            id=_public_ip_resource_id(subscription_id="fake-subscription-2", resource_name="fake-public-ipv4-baz-1"),
            ip_address="204.13.0.121",
        )

        test_subscription_1_appgws = [foo_appgw, bar_appgw]
        test_subscription_2_appgws = [baz_appgw]
        test_public_ips = [foo_public_ip, baz_public_ip]

        list_subscriptions_mock.return_value = [test_subscription_1, test_subscription_2]
        list_all_appgw_mock.side_effect = [test_subscription_1_appgws, test_subscription_2_appgws]
        get_public_ip_mock.side_effect = [ip for ip in test_public_ips]

        options = [
            {"name": "azureTenant", "value": "mockedTenant"},
            {"name": "azureAppID", "value": "mockedAppID"},
            {"name": "azurePassword", "value": "mockedPW"},
            {"name": "authenticationMethod", "value": "azureApp"}
        ]
        synced_endpoints = self.azure_source.get_endpoints(options)
        assert synced_endpoints == [
            dict(
                name="fake-appgw-foo-public-443",
                dnsname="204.13.0.120",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-foo",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
            ),
            dict(
                name="fake-appgw-baz-public-443",
                dnsname="204.13.0.121",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-baz-1",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
            ),
            dict(
                name="fake-appgw-baz-internal-443",
                dnsname="10.10.200.1",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-baz-2",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
            ),
        ]
