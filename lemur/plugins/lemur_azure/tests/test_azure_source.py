import os
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from lemur.plugins.lemur_azure import plugin

from azure.mgmt.subscription.models import Subscription
from azure.mgmt.network.models import (
    ApplicationGateway,
    ApplicationGatewayFrontendIPConfiguration,
    ApplicationGatewayFrontendPort,
    ApplicationGatewayHttpListener,
    ApplicationGatewaySslPredefinedPolicy,
    ApplicationGatewaySslCertificate,
    ApplicationGatewaySslPolicy,
    ApplicationGatewaySslPolicyName,
    ApplicationGatewaySslPolicyType,
    ApplicationGatewaySslCipherSuite,
    PublicIPAddress,
    SubResource
)
from azure.keyvault.certificates import CertificateProperties, KeyVaultCertificate


test_server_cert_1 = """-----BEGIN CERTIFICATE-----
MIIDsDCCApigAwIBAgIJAIezI4YBdaH5MA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNV
BAYTAkFUMQ8wDQYDVQQHDAZWaWVubmExEDAOBgNVBAoMB1NpcmZlcmwxETAPBgNV
BAMMCExvY2FsIENBMSEwHwYJKoZIhvcNAQkBFhJzaXJmZXJsQGdpdGh1Yi5jb20w
HhcNMjEwNzI0MDM1MDIzWhcNMjIxMjA2MDM1MDIzWjBnMQswCQYDVQQGEwJBVDEP
MA0GA1UEBwwGVmllbm5hMRAwDgYDVQQKDAdTaXJmZXJsMSEwHwYJKoZIhvcNAQkB
FhJzaXJmZXJsQGdpdGh1Yi5jb20xEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALR59JM38ltmUDAjQiohKjsB/xkRM86P
ZlsKlL78yTA/XRbrIHDq+88InQajr+R4sq26MmCaAbHBuwn7RCVh2o/letI14WBL
wvYIk1RGxwIFR2nNkQfTMfweK3aHLiL1714pW3cZbGgqGNmP4V5BQLI4eMDu6I9O
WmGWL+HDJsn7ug55aNBV8qxiYIzAQm87bqbBBHbB6ht98SjVPG9kYT4hdxmaQ0lo
eb+hJ6LKcwEN6shyz3bWQ4p2ngglOYQ+D9SNxOH6GHAh72jQr3Pz0iU49D6HUOGg
QXKzV4nl2JFsA+nd8swoHhqmNMAvNgjv5ydaRFwWDdCiyhT8PNGOeFECAwEAAaNg
MF4wHwYDVR0jBBgwFoAUf09uS3ulWhvipHzUkEVskyhfAUcwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwIwYDVR0RBBwwGoINbXlleGFtcGxlLmNvbYIJbG9jYWxob3N0
MA0GCSqGSIb3DQEBCwUAA4IBAQBS/7o0fMhDX2k0dc5S8cVxBhg8BPVqas99E8g3
bDKnFcUdv4KTVgdYRbQ+o8DMkWZVDwyRDs5f2v9dyWtMk33jtxjs8UTXCmIhNgLg
oSd+GXhOxThRj9euiyP/NA0JbCdrv4z5UEWZ2+U+lsLALoXBZqQAgDpZNggsujqn
o0BydDBcgoQtQ3w5e9k5Upah6f+X0ZryXQemC/BnjKSdXipkcg295WyV780jTQV1
9+NK9wF8ED74VGLaqAHjTT2UmVfiyPs7kxU+KqYzLfl2GL49RDcf4V06q5pr/JmR
tXwUxRyH8L1hRMfyCE/35EhVTmPdc3lRaPXROD1gtuRDEQIb
-----END CERTIFICATE-----
"""

test_server_cert_2 = """-----BEGIN CERTIFICATE-----
MIIEJDCCAwygAwIBAgIPK/QvcZhAY7VPU7Ek/nCDMA0GCSqGSIb3DQEBCwUAMIGn
MS0wKwYDVQQDDCRMZW11clRydXN0IFVuaXR0ZXN0cyBDbGFzcyAxIENBIDIwMTgx
IzAhBgNVBAoMGkxlbXVyVHJ1c3QgRW50ZXJwcmlzZXMgTHRkMSYwJAYDVQQLDB1V
bml0dGVzdGluZyBPcGVyYXRpb25zIENlbnRlcjELMAkGA1UEBhMCRUUxDDAKBgNV
BAgMA04vQTEOMAwGA1UEBwwFRWFydGgwHhcNMTcxMjMxMjIwMDAwWhcNNDcxMjMx
MjIwMDAwWjB9MRswGQYDVQQDDBIqLndpbGQuZXhhbXBsZS5vcmcxETAPBgNVBAoM
CFBsYXl0ZWNoMRkwFwYDVQQLDBBJbmZyYSBPcGVyYXRpb25zMQswCQYDVQQGEwJF
RTERMA8GA1UECAwISGFyanVtYWExEDAOBgNVBAcMB1RhbGxpbm4wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoT8Ak5kynUzosBvP8hCnP4hGMAtgHLcHG
UBWug4BofAhxxBrZW3UteoQzNznK5jz0hy2azqnz3/9q5N/FKwHxfMY/VEHPXyYK
QsZuSdVceJ/EHL+MLx+uisIRJstV8fC5oYRfg74m07ZED7NM4EerJTxKZAy7UuSM
L65i/LEChPzjLN46GcUEuC2O03nZtFTPvN9j7vzen9/qIzs1TGQukOn4z5l2GuAx
RCEfBl3IrnvSY+npGARPJsXSymXCCP3ntzq6I6iRHuZf+QETZtiMR1TCNZRTqcc2
LxWn+W5N18yyXvUcVMfrg4jzEWKHuhwInoiH1pu/myyKrnoIi4nTAgMBAAGjdjB0
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8E
AjAAMB0GA1UdDgQWBBRR9Q9DHJRPt69Qm8lir4iJfOmJ4TAgBgNVHREBAf8EFjAU
ghIqLndpbGQuZXhhbXBsZS5vcmcwDQYJKoZIhvcNAQELBQADggEBAMm2DiYfGLve
r/gCtYgXKkRmbuv57PmAUm52w5l4hjxssdUwq4Wn4T+K0+Sqp3IzcNhEaIqPB+bG
8rIbJLBiiDPbSUZC0DbvlXihk7FHjqmrbVFwNmkWNywLhB1qOlp0kQH+w9lDWA1p
y99P0Bxcot66scbiaag0i0AUpkRKbUG+v+VGXdPrJrWE+63ROhWQMmQNiUlZ6QGO
45tUSn//MuUpJiJVkUVR1fSbCpHQj2mHiuhShOmatmh5e1ISwVP19cX64Gr6djlY
wKJqcmw7WDjl+T+y7luJWw4UqI7s7hY6Y9RQVh61L4eV8CIma3NmTaQCSgR3tCxh
d4FCKAE8+Lw=
-----END CERTIFICATE-----
"""


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
        self.options = [
            {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
            {"name": "azureTenant", "value": "mockedTenant"},
            {"name": "azureAppID", "value": "mockedAppID"},
            {"name": "azurePassword", "value": "mockedPW"},
            {"name": "authenticationMethod", "value": "azureApp"}
        ]

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.keyvault.certificates.CertificateClient.get_certificate")
    def test_get_certificate_by_name(self, get_certificate_mock):
        fake_crt = x509.load_pem_x509_certificate(str.encode(test_server_cert_1))
        fake_cer_contents = fake_crt.public_bytes(encoding=serialization.Encoding.DER)
        kv_cert = KeyVaultCertificate(cer=fake_cer_contents)
        get_certificate_mock.return_value = kv_cert

        crt = self.azure_source.get_certificate_by_name("localhost-LocalCA", self.options)
        assert crt["body"] == test_server_cert_1

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.keyvault.certificates.CertificateClient.get_certificate")
    @patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates")
    def test_get_certificates(self, list_properties_of_certificates_mock, get_certificate_mock):
        test_crt_1 = x509.load_pem_x509_certificate(str.encode(test_server_cert_1))
        test_crt_1_contents = test_crt_1.public_bytes(encoding=serialization.Encoding.DER)
        test_crt_2 = x509.load_pem_x509_certificate(str.encode(test_server_cert_2))
        test_crt_2_contents = test_crt_2.public_bytes(encoding=serialization.Encoding.DER)
        test_properties = [
            CertificateProperties(cert_id="https://couldbeanyvalue.com/certificates/localhost-LocalCA/1234abc"),
            CertificateProperties(cert_id="https://couldbeanyvalue.com/certificates/star-wild-example-org-LemurTrust/1234abc"),
        ]
        test_certificates = [
            KeyVaultCertificate(
                properties=test_properties[0],
                cer=test_crt_1_contents,
            ),
            KeyVaultCertificate(
                properties=test_properties[1],
                cer=test_crt_2_contents,
            )
        ]

        list_properties_of_certificates_mock.return_value = test_properties
        get_certificate_mock.side_effect = [c for c in test_certificates]

        synced_certificates = self.azure_source.get_certificates(self.options)
        assert synced_certificates == [
            dict(
                name="localhost-LocalCA",
                body=test_crt_1.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"),
            ),
            dict(
                name="star-wild-example-org-LemurTrust",
                body=test_crt_2.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8"),
            ),
        ]

        pass

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.mgmt.network.v2022_05_01.operations.PublicIPAddressesOperations.get")
    @patch("azure.mgmt.network.v2022_05_01.operations.ApplicationGatewaysOperations.get_ssl_predefined_policy")
    @patch("azure.mgmt.network.v2022_05_01.operations.ApplicationGatewaysOperations.list_all")
    @patch("azure.mgmt.subscription.operations.SubscriptionsOperations.list")
    def test_get_endpoints(
            self,
            list_subscriptions_mock,
            list_all_appgw_mock,
            get_ssl_predefined_policy_mock,
            get_public_ip_mock
    ):
        test_subscription_1 = Subscription()
        test_subscription_1.subscription_id = "fake-subscription-1"
        test_subscription_2 = Subscription()
        test_subscription_2.subscription_id = "fake-subscription-2"

        test_predefined_ssl_policy = ApplicationGatewaySslPredefinedPolicy(
            predefined_policy_name="AppGwSslPolicy20170401S",
            cipher_suites=[
                ApplicationGatewaySslCipherSuite("TLS_RSA_WITH_AES_256_CBC_SHA"),
            ]
        )
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
            ssl_policy=ApplicationGatewaySslPolicy(
                policy_name=ApplicationGatewaySslPolicyName("AppGwSslPolicy20170401S"),
                policy_type=ApplicationGatewaySslPolicyType("Predefined"),
            ),
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
                    port=80,
                ),
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
            ssl_policy=ApplicationGatewaySslPolicy(
                policy_name="UserDefinedCustomAppGwSslPolicy",
                policy_type=ApplicationGatewaySslPolicyType("CustomV2"),
                cipher_suites=[
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                ]
            ),
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
        get_ssl_predefined_policy_mock.return_value = test_predefined_ssl_policy

        synced_endpoints = self.azure_source.get_endpoints(self.options)
        assert synced_endpoints == [
            dict(
                name="fake-appgw-foo-public-443",
                dnsname="204.13.0.120",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-foo",
                    path="",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
                policy=dict(
                    name="AppGwSslPolicy20170401S",
                    ciphers=["TLS_RSA_WITH_AES_256_CBC_SHA"],
                )
            ),
            dict(
                name="fake-appgw-baz-public-443",
                dnsname="204.13.0.121",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-baz-1",
                    path="",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
                policy=dict(
                    name="UserDefinedCustomAppGwSslPolicy",
                    ciphers=["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
                )
            ),
            dict(
                name="fake-appgw-baz-internal-443",
                dnsname="10.10.200.1",
                port=443,
                type="applicationgateway",
                primary_certificate=dict(
                    name="fake-ssl-certificate-baz-2",
                    path="",
                    registry_type="keyvault",
                ),
                sni_certificates=[],
                policy=dict(
                    name="UserDefinedCustomAppGwSslPolicy",
                    ciphers=["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
                )
            ),
        ]
