import unittest
from unittest.mock import patch, Mock

from cryptography.x509 import DNSName
from lemur.plugins.lemur_acme import plugin


class TestAcmeHandler(unittest.TestCase):
    def setUp(self):
        self.acme = plugin.AcmeHandler()

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
