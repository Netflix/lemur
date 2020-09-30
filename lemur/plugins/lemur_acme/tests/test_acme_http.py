import unittest
from unittest.mock import patch, Mock

from acme import challenges
from lemur.plugins.lemur_acme import plugin
from mock import MagicMock


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

    @patch("acme.client.Client")
    @patch("OpenSSL.crypto", return_value="mock_cert")
    @patch("josepy.util.ComparableX509")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_dns_challenges")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_request_certificate(
            self,
            mock_current_app,
            mock_get_dns_challenges,
            mock_jose,
            mock_crypto,
            mock_acme,
    ):
        mock_cert_response = Mock()
        mock_cert_response.body = "123"
        mock_cert_response_full = [mock_cert_response, True]
        mock_acme.poll_and_request_issuance = Mock(return_value=mock_cert_response_full)
        mock_authz = []
        mock_authz_record = MagicMock()
        mock_authz_record.authz = Mock()
        mock_authz.append(mock_authz_record)
        mock_acme.fetch_chain = Mock(return_value="mock_chain")
        mock_crypto.dump_certificate = Mock(return_value=b"chain")
        mock_order = Mock()
        mock_current_app.config = {}
        self.acme.request_certificate(mock_acme, [], mock_order)

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

        mock_dns_provider = Mock()
        mock_dns_provider.credentials = '{"account_id": 1}'
        mock_dns_provider.provider_type = "route53"
        mock_dns_provider_service.get.return_value = mock_dns_provider

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
