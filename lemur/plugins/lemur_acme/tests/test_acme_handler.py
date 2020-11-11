import unittest
from unittest.mock import patch, Mock

from flask import Flask
from cryptography.x509 import DNSName
from lemur.plugins.lemur_acme import acme_handlers


class TestAcmeHandler(unittest.TestCase):
    def setUp(self):
        self.acme = acme_handlers.AcmeHandler()

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_acme')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_strip_wildcard(self):
        expected = ("example.com", False)
        result = self.acme.strip_wildcard("example.com")
        self.assertEqual(expected, result)

        expected = ("example.com", True)
        result = self.acme.strip_wildcard("*.example.com")
        self.assertEqual(expected, result)

    def test_authz_record(self):
        a = acme_handlers.AuthorizationRecord("domain", "host", "authz", "challenge", "id")
        self.assertEqual(type(a), acme_handlers.AuthorizationRecord)

    def test_setup_acme_client_fail(self):
        mock_authority = Mock()
        mock_authority.options = []
        with self.assertRaises(Exception):
            self.acme.setup_acme_client(mock_authority)

    def test_reuse_account_not_defined(self):
        mock_authority = Mock()
        mock_authority.options = []
        with self.assertRaises(Exception):
            self.acme.reuse_account(mock_authority)

    def test_reuse_account_from_authority(self):
        mock_authority = Mock()
        mock_authority.options = '[{"name": "acme_private_key", "value": "PRIVATE_KEY"}, {"name": "acme_regr", "value": "ACME_REGR"}]'

        self.assertTrue(self.acme.reuse_account(mock_authority))

    @patch("lemur.plugins.lemur_acme.acme_handlers.current_app")
    def test_reuse_account_from_config(self, mock_current_app):
        mock_authority = Mock()
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}]'
        mock_current_app.config = {"ACME_PRIVATE_KEY": "PRIVATE_KEY", "ACME_REGR": "ACME_REGR"}

        self.assertTrue(self.acme.reuse_account(mock_authority))

    def test_reuse_account_no_configuration(self):
        mock_authority = Mock()
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}]'

        self.assertFalse(self.acme.reuse_account(mock_authority))

    @patch("lemur.plugins.lemur_acme.acme_handlers.authorities_service")
    @patch("lemur.plugins.lemur_acme.acme_handlers.BackwardsCompatibleClientV2")
    def test_setup_acme_client_success(self, mock_acme, mock_authorities_service):
        mock_authority = Mock()
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}, ' \
                                 '{"name": "store_account", "value": false}]'
        mock_client = Mock()
        mock_registration = Mock()
        mock_registration.uri = "http://test.com"
        mock_client.register = mock_registration
        mock_client.agree_to_tos = Mock(return_value=True)
        mock_acme.return_value = mock_client
        result_client, result_registration = self.acme.setup_acme_client(mock_authority)
        mock_authorities_service.update_options.assert_not_called()
        assert result_client
        assert result_registration

    def test_get_domains_single(self):
        options = {"common_name": "test.netflix.net"}
        result = self.acme.get_domains(options)
        self.assertEqual(result, [options["common_name"]])

    def test_get_domains_multiple(self):
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

    def test_get_domains_san(self):
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
