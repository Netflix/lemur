import unittest
from unittest.mock import patch, Mock

from cryptography.x509 import DNSName
from lemur.plugins.lemur_acme import plugin
from mock import MagicMock


class TestAcmeHandler(unittest.TestCase):
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    def setUp(self, mock_dns_provider_service):
        self.acme = plugin.AcmeHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "cloudflare"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "cloudflare"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }

    def test_strip_wildcard(self):
        expected = ("example.com", False)
        result = self.acme.strip_wildcard("example.com")
        self.assertEqual(expected, result)

        expected = ("example.com", True)
        result = self.acme.strip_wildcard("*.example.com")
        self.assertEqual(expected, result)

    def test_authz_record(self):
        a = plugin.AuthorizationRecord("host", "authz", "challenge", "id")
        self.assertEqual(type(a), plugin.AuthorizationRecord)

    def test_setup_acme_client_fail(self):
        mock_authority = Mock()
        mock_authority.options = []
        with self.assertRaises(Exception):
            self.acme.setup_acme_client(mock_authority)

    @patch("lemur.plugins.lemur_acme.plugin.BackwardsCompatibleClientV2")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_setup_acme_client_success(self, mock_current_app, mock_acme):
        mock_authority = Mock()
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}]'
        mock_client = Mock()
        mock_registration = Mock()
        mock_registration.uri = "http://test.com"
        mock_client.register = mock_registration
        mock_client.agree_to_tos = Mock(return_value=True)
        mock_acme.return_value = mock_client
        mock_current_app.config = {}
        result_client, result_registration = self.acme.setup_acme_client(mock_authority)
        assert result_client
        assert result_registration

    @patch('lemur.plugins.lemur_acme.plugin.current_app')
    def test_get_domains_single(self, mock_current_app):
        options = {"common_name": "test.netflix.net"}
        result = self.acme.get_domains(options)
        self.assertEqual(result, [options["common_name"]])

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_get_domains_multiple(self, mock_current_app):
        options = {
            "common_name": "test.netflix.net",
            "extensions": {
                "sub_alt_names": {"names": [DNSName("test2.netflix.net"), DNSName("test3.netflix.net")]}
            },
        }
        result = self.acme.get_domains(options)
        self.assertEqual(
            result, [options["common_name"], "test2.netflix.net", "test3.netflix.net"]
        )

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_get_domains_san(self, mock_current_app):
        options = {
            "common_name": "test.netflix.net",
            "extensions": {
                "sub_alt_names": {"names": [DNSName("test.netflix.net"), DNSName("test2.netflix.net")]}
            },
        }
        result = self.acme.get_domains(options)
        self.assertEqual(
            result, [options["common_name"], "test2.netflix.net"]
        )

    @patch(
        "lemur.plugins.lemur_acme.plugin.AcmeHandler.start_dns_challenge",
        return_value="test",
    )
    def test_get_authorizations(self, mock_start_dns_challenge):
        mock_order = Mock()
        mock_order.body.identifiers = []
        mock_domain = Mock()
        mock_order.body.identifiers.append(mock_domain)
        mock_order_info = Mock()
        mock_order_info.account_number = 1
        mock_order_info.domains = ["test.fakedomain.net"]
        result = self.acme.get_authorizations(
            "acme_client", mock_order, mock_order_info
        )
        self.assertEqual(result, ["test"])

    @patch(
        "lemur.plugins.lemur_acme.plugin.AcmeHandler.complete_dns_challenge",
        return_value="test",
    )
    def test_finalize_authorizations(self, mock_complete_dns_challenge):
        mock_authz = []
        mock_authz_record = MagicMock()
        mock_authz_record.authz = Mock()
        mock_authz_record.change_id = 1
        mock_authz_record.dns_challenge.validation_domain_name = Mock()
        mock_authz_record.dns_challenge.validation = Mock()
        mock_authz.append(mock_authz_record)
        mock_dns_provider = Mock()
        mock_dns_provider.delete_txt_record = Mock()

        mock_acme_client = Mock()
        result = self.acme.finalize_authorizations(mock_acme_client, mock_authz)
        self.assertEqual(result, mock_authz)

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    def test_get_ordered_certificate(
            self,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_dns_provider_service,
            mock_authorization_service,
            mock_current_app,
            mock_acme,
    ):
        mock_client = Mock()
        mock_acme.return_value = (mock_client, "")
        mock_request_certificate.return_value = ("pem_certificate", "chain")

        mock_cert = Mock()
        mock_cert.external_id = 1

        provider = plugin.ACMEIssuerPlugin()
        provider.get_dns_provider = Mock()
        result = provider.get_ordered_certificate(mock_cert)
        self.assertEqual(
            result, {"body": "pem_certificate", "chain": "chain", "external_id": "1"}
        )

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    def test_get_ordered_certificates(
            self,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_dns_provider_service,
            mock_authorization_service,
            mock_current_app,
            mock_acme,
    ):
        mock_client = Mock()
        mock_acme.return_value = (mock_client, "")
        mock_request_certificate.return_value = ("pem_certificate", "chain")

        mock_cert = Mock()
        mock_cert.external_id = 1

        mock_cert2 = Mock()
        mock_cert2.external_id = 2

        provider = plugin.ACMEIssuerPlugin()
        provider.get_dns_provider = Mock()
        result = provider.get_ordered_certificates([mock_cert, mock_cert2])
        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[0]["cert"],
            {"body": "pem_certificate", "chain": "chain", "external_id": "1"},
        )
        self.assertEqual(
            result[1]["cert"],
            {"body": "pem_certificate", "chain": "chain", "external_id": "2"},
        )
