import unittest
from unittest.mock import patch, Mock

from acme import challenges
from flask import Flask
from lemur.plugins.lemur_acme import plugin

from lemur.tests.vectors import ACME_CHAIN_LONG_STR, SAN_CERT_STR, ACME_CHAIN_X1_STR


class TestAcmeHttp(unittest.TestCase):

    def setUp(self):
        self.ACMEHttpIssuerPlugin = plugin.ACMEHttpIssuerPlugin()
        self.acme = plugin.AcmeHandler()

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask("lemur_test_acme")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_create_authority(self):
        options = {
            "plugin": {"plugin_options": [{"name": "certificate", "value": "123"}]},
            "name": "mock_authority",
        }
        acme_root, b, role = self.ACMEHttpIssuerPlugin.create_authority(options)
        self.assertEqual(acme_root, "123")
        self.assertEqual(b, "")
        self.assertEqual(
            role,
            [{"username": "", "password": "", "name": "acme_mock_authority_admin"}],
        )

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.challenge_types.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate(
        self,
        mock_authorization_service,
        mock_request_certificate,
        mock_destination_service,
        mock_plugin_manager_get,
        mock_acme,
    ):
        provider = plugin.ACMEHttpIssuerPlugin()
        mock_authority = Mock()
        mock_authority.options = (
            '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'
        )

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[
            0
        ].response_and_validation.return_value = (Mock(), "Anything-goes")
        mock_order_resource.authorizations[0].body.challenges[0].chall = (
            challenges.HTTP01(
                token=b"\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f"
            )
        )

        mock_client = Mock()
        mock_client.new_order.return_value = mock_order_resource
        mock_client.answer_challenge.return_value = True

        mock_finalized_order = Mock()
        mock_finalized_order.fullchain_pem = ACME_CHAIN_LONG_STR

        mock_finalized_order.alternative_fullchains_pem = [
            mock_finalized_order.fullchain_pem
        ]
        mock_finalized_order.authorizations = [Mock()]
        mock_client.finalize_order.return_value = mock_finalized_order

        mock_acme.return_value = (mock_client, "")

        mock_destination = Mock()
        mock_destination.label = "mock-sftp-destination"
        mock_destination.plugin_name = "SFTPDestinationPlugin"
        mock_destination_service.get.return_value = mock_destination

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
        pem_certificate, pem_certificate_chain, _ = provider.create_certificate(
            csr, issuer_options
        )

        self.assertEqual(pem_certificate, SAN_CERT_STR)
        self.assertEqual(
            pem_certificate_chain, ACME_CHAIN_LONG_STR[len(SAN_CERT_STR) :].lstrip()
        )
        mock_authority.options = (
            '[{"name": "tokenDestination", "value": "mock-sftp-destination"},'
            '{"name": "drop_last_cert_from_chain", "value": true}]'
        )

        pem_certificate, pem_certificate_chain, _ = provider.create_certificate(
            csr, issuer_options
        )

        self.assertEqual(pem_certificate, SAN_CERT_STR)
        self.assertEqual(pem_certificate_chain, ACME_CHAIN_X1_STR)

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.challenge_types.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate_missing_destination_token(
        self,
        mock_authorization_service,
        mock_request_certificate,
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
        mock_order_resource.authorizations[0].body.challenges[0].chall = (
            challenges.HTTP01(
                token=b"\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f"
            )
        )

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
        with self.assertRaisesRegex(Exception, "No token_destination configured"):
            provider.create_certificate(csr, issuer_options)

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.base.manager.PluginManager.get")
    @patch("lemur.plugins.lemur_acme.challenge_types.destination_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    def test_create_certificate_missing_http_challenge(
        self,
        mock_authorization_service,
        mock_request_certificate,
        mock_destination_service,
        mock_plugin_manager_get,
        mock_acme,
    ):
        provider = plugin.ACMEHttpIssuerPlugin()
        mock_authority = Mock()
        mock_authority.options = (
            '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'
        )

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].chall = (
            challenges.DNS01(
                token=b"\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f"
            )
        )

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
        with self.assertRaisesRegex(Exception, "HTTP-01 challenge was not offered"):
            provider.create_certificate(csr, issuer_options)
