import unittest
from unittest.mock import patch, Mock

from acme import challenges
from lemur.plugins.lemur_acme import plugin


class TestAcmeHttp(unittest.TestCase):
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.destination_service")
    def setUp(self, mock_dns_provider_service, mock_destination_provider):
        self.ACMEHttpIssuerPlugin = plugin.ACMEHttpIssuerPlugin()
        self.acme = plugin.AcmeHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "cloudflare"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "cloudflare"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }
        mock_destination_provider = Mock()
        mock_destination_provider.label = "mock-sftp-destination"
        mock_destination_provider.plugin_name = "sftp-destination"
        self.ACMEHttpIssuerPlugin.destination_list = ["mock-sftp-destination", "mock-s3-destination"]

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_create_authority(self, mock_current_app):
        mock_current_app.config = Mock()
        options = {
            "plugin": {"plugin_options": [{"name": "certificate", "value": "123"}]}
        }
        acme_root, b, role = self.ACMEHttpIssuerPlugin.create_authority(options)
        self.assertEqual(acme_root, "123")
        self.assertEqual(b, "")
        self.assertEqual(role, [{"username": "", "password": "", "name": "acme"}])

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.plugin.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate(
            self,
            mock_authorization_service,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_current_app,
            mock_dns_provider_service,
            mock_destination_service,
            mock_plugin_manager_get,
            mock_acme,
    ):
        provider = plugin.ACMEHttpIssuerPlugin()
        mock_authority = Mock()
        mock_authority.options = '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.HTTP01(token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

        mock_client = Mock()
        mock_client.new_order.return_value = mock_order_resource
        mock_acme.return_value = (mock_client, "")

        mock_destination = Mock()
        mock_destination.label = "mock-sftp-destination"
        mock_destination.plugin_name = "SFTPDestinationPlugin"
        mock_destination_service.get_by_label.return_value = mock_destination

        mock_destination_plugin = Mock()
        mock_destination_plugin.upload_acme_token.return_value = True
        mock_plugin_manager_get.return_value = mock_destination_plugin

        issuer_options = {
            "authority": mock_authority,
            "tokenDestination": "mock-sftp-destination",
            "common_name": "test.netflix.net",
        }
        csr = "123"
        mock_request_certificate.return_value = ("pem_certificate", "chain")
        result = provider.create_certificate(csr, issuer_options)
        assert result

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.plugin.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate_missing_destination_token(
            self,
            mock_authorization_service,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_current_app,
            mock_dns_provider_service,
            mock_destination_service,
            mock_plugin_manager_get,
            mock_acme,
    ):
        provider = plugin.ACMEHttpIssuerPlugin()
        mock_authority = Mock()
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}]'

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.HTTP01(
            token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

        mock_client = Mock()
        mock_client.new_order.return_value = mock_order_resource
        mock_acme.return_value = (mock_client, "")

        mock_destination = Mock()
        mock_destination.label = "mock-sftp-destination"
        mock_destination.plugin_name = "SFTPDestinationPlugin"
        mock_destination_service.get_by_label.return_value = mock_destination

        mock_destination_plugin = Mock()
        mock_destination_plugin.upload_acme_token.return_value = True
        mock_plugin_manager_get.return_value = mock_destination_plugin

        issuer_options = {
            "authority": mock_authority,
            "tokenDestination": "mock-sftp-destination",
            "common_name": "test.netflix.net",
        }
        csr = "123"
        mock_request_certificate.return_value = ("pem_certificate", "chain")
        with self.assertRaisesRegexp(Exception, "No token_destination configured"):
            provider.create_certificate(csr, issuer_options)

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.plugin.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate_missing_http_challenge(
            self,
            mock_authorization_service,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_current_app,
            mock_dns_provider_service,
            mock_destination_service,
            mock_plugin_manager_get,
            mock_acme,
    ):
        provider = plugin.ACMEHttpIssuerPlugin()
        mock_authority = Mock()
        mock_authority.options = '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.DNS01(
            token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

        mock_client = Mock()
        mock_client.new_order.return_value = mock_order_resource
        mock_acme.return_value = (mock_client, "")

        issuer_options = {
            "authority": mock_authority,
            "tokenDestination": "mock-sftp-destination",
            "common_name": "test.netflix.net",
        }
        csr = "123"
        mock_request_certificate.return_value = ("pem_certificate", "chain")
        with self.assertRaisesRegexp(Exception, "HTTP-01 challenge was not offered"):
            provider.create_certificate(csr, issuer_options)
