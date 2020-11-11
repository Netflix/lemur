import unittest
from unittest.mock import patch, Mock

import josepy as jose
from cryptography.x509 import DNSName
from flask import Flask
from lemur.plugins.lemur_acme import plugin
from lemur.plugins.lemur_acme.acme_handlers import AuthorizationRecord
from lemur.common.utils import generate_private_key
from mock import MagicMock


class TestAcmeDns(unittest.TestCase):
    @patch("lemur.plugins.lemur_acme.acme_handlers.dns_provider_service")
    def setUp(self, mock_dns_provider_service):
        self.ACMEIssuerPlugin = plugin.ACMEIssuerPlugin()
        self.acme = plugin.AcmeDnsHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "cloudflare"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "cloudflare"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_acme')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("lemur.plugins.lemur_acme.plugin.len", return_value=1)
    def test_get_dns_challenges(self, mock_len):
        assert mock_len

        from acme import challenges

        host = "example.com"
        c = challenges.DNS01()

        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = Mock()
        mock_entry.chall = c
        mock_authz.body.resolved_combinations.append(mock_entry)
        result = yield self.acme.get_dns_challenges(host, mock_authz)
        self.assertEqual(result, mock_entry)

    @patch("acme.client.Client")
    @patch("lemur.plugins.lemur_acme.plugin.len", return_value=1)
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.get_dns_challenges")
    def test_start_dns_challenge(
            self, mock_get_dns_challenges, mock_len, mock_acme
    ):
        assert mock_len
        mock_order = Mock()
        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = MagicMock()

        mock_entry.chall = TestAcmeDns.test_complete_dns_challenge_fail
        mock_authz.body.resolved_combinations.append(mock_entry)
        mock_acme.request_domain_challenges = Mock(return_value=mock_authz)
        mock_dns_provider = Mock()
        mock_dns_provider.create_txt_record = Mock(return_value=1)

        values = [mock_entry]
        iterable = mock_get_dns_challenges.return_value
        iterator = iter(values)
        iterable.__iter__.return_value = iterator
        result = self.acme.start_dns_challenge(
            mock_acme, "accountid", "domain", "host", mock_dns_provider, mock_order, {}
        )
        self.assertEqual(type(result), AuthorizationRecord)

    @patch("acme.client.Client")
    @patch("lemur.plugins.lemur_acme.cloudflare.wait_for_dns_change")
    @patch("time.sleep")
    def test_complete_dns_challenge_success(
            self, mock_sleep, mock_wait_for_dns_change, mock_acme
    ):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)
        mock_authz = Mock()
        mock_sleep.return_value = False
        mock_authz.dns_challenge.response = Mock()
        mock_authz.dns_challenge.response.simple_verify = Mock(return_value=True)
        mock_authz.authz = []
        mock_authz.target_domain = "www.test.com"
        mock_authz_record = Mock()
        mock_authz_record.body.identifier.value = "test"
        mock_authz.authz.append(mock_authz_record)
        mock_authz.change_id = []
        mock_authz.change_id.append("123")
        mock_authz.dns_challenge = []
        dns_challenge = Mock()
        mock_authz.dns_challenge.append(dns_challenge)
        self.acme.complete_dns_challenge(mock_acme, mock_authz)

    @patch("acme.client.Client")
    @patch("lemur.plugins.lemur_acme.cloudflare.wait_for_dns_change")
    def test_complete_dns_challenge_fail(
            self, mock_wait_for_dns_change, mock_acme
    ):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)

        mock_dns_challenge = Mock()
        response = Mock()
        response.simple_verify = Mock(return_value=False)
        mock_dns_challenge.response = Mock(return_value=response)

        mock_authz = Mock()
        mock_authz.dns_challenge = []
        mock_authz.dns_challenge.append(mock_dns_challenge)

        mock_authz.target_domain = "www.test.com"
        mock_authz_record = Mock()
        mock_authz_record.body.identifier.value = "test"
        mock_authz.authz = []
        mock_authz.authz.append(mock_authz_record)
        mock_authz.change_id = []
        mock_authz.change_id.append("123")
        with self.assertRaises(ValueError):
            self.acme.complete_dns_challenge(mock_acme, mock_authz)

    @patch("acme.client.Client")
    @patch("OpenSSL.crypto", return_value="mock_cert")
    @patch("josepy.util.ComparableX509")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.get_dns_challenges")
    def test_request_certificate(
            self,
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
        self.acme.request_certificate(mock_acme, [], mock_order)

    def test_setup_acme_client_fail(self):
        mock_authority = Mock()
        mock_authority.options = []
        with self.assertRaises(Exception):
            self.acme.setup_acme_client(mock_authority)

    @patch("lemur.plugins.lemur_acme.acme_handlers.jose.JWK.json_loads")
    @patch("lemur.plugins.lemur_acme.acme_handlers.BackwardsCompatibleClientV2")
    def test_setup_acme_client_success_load_account_from_authority(self, mock_acme, mock_key_json_load):
        mock_authority = Mock()
        mock_authority.id = 2
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}, ' \
                                 '{"name": "store_account", "value": true},' \
                                 '{"name": "acme_private_key", "value": "{\\"n\\": \\"PwIOkViO\\", \\"kty\\": \\"RSA\\"}"}, ' \
                                 '{"name": "acme_regr", "value": "{\\"body\\": {}, \\"uri\\": \\"http://test.com\\"}"}]'
        mock_client = Mock()
        mock_acme.return_value = mock_client

        mock_key_json_load.return_value = jose.JWKRSA(key=generate_private_key("RSA2048"))

        result_client, result_registration = self.acme.setup_acme_client(mock_authority)

        mock_acme.new_account_and_tos.assert_not_called()
        assert result_client
        assert not result_registration

    @patch("lemur.plugins.lemur_acme.acme_handlers.jose.JWKRSA.fields_to_partial_json")
    @patch("lemur.plugins.lemur_acme.acme_handlers.authorities_service")
    @patch("lemur.plugins.lemur_acme.acme_handlers.BackwardsCompatibleClientV2")
    def test_setup_acme_client_success_store_new_account(self, mock_acme, mock_authorities_service,
                                                         mock_key_generation):
        mock_authority = Mock()
        mock_authority.id = 2
        mock_authority.options = '[{"name": "mock_name", "value": "mock_value"}, ' \
                                 '{"name": "store_account", "value": true}]'
        mock_client = Mock()
        mock_registration = Mock()
        mock_registration.uri = "http://test.com"
        mock_client.register = mock_registration
        mock_client.agree_to_tos = Mock(return_value=True)
        mock_client.new_account_and_tos.return_value = mock_registration
        mock_acme.return_value = mock_client

        mock_key_generation.return_value = {"n": "PwIOkViO"}

        mock_authorities_service.update_options = Mock(return_value=True)

        self.acme.setup_acme_client(mock_authority)

        mock_authorities_service.update_options.assert_called_with(2, options='[{"name": "mock_name", "value": "mock_value"}, '
        '{"name": "store_account", "value": true}, '
        '{"name": "acme_private_key", "value": "{\\"n\\": \\"PwIOkViO\\", \\"kty\\": \\"RSA\\"}"}, '
        '{"name": "acme_regr", "value": "{\\"body\\": {}, \\"uri\\": \\"http://test.com\\"}"}]')

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

    def test_create_authority(self):
        options = {
            "plugin": {"plugin_options": [{"name": "certificate", "value": "123"}]}
        }
        acme_root, b, role = self.ACMEIssuerPlugin.create_authority(options)
        self.assertEqual(acme_root, "123")
        self.assertEqual(b, "")
        self.assertEqual(role, [{"username": "", "password": "", "name": "acme"}])

    @patch("lemur.plugins.lemur_acme.acme_handlers.dns_provider_service")
    def test_get_dns_provider(self, mock_dns_provider_service):
        provider = plugin.AcmeDnsHandler()
        route53 = provider.get_dns_provider("route53")
        assert route53
        cloudflare = provider.get_dns_provider("cloudflare")
        assert cloudflare
        dyn = provider.get_dns_provider("dyn")
        assert dyn

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
    @patch("lemur.plugins.lemur_acme.acme_handlers.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.request_certificate")
    @patch("lemur.plugins.lemur_acme.challenge_types.authorization_service")
    def test_create_certificate(
            self,
            mock_authorization_service,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_dns_provider_service,
            mock_acme,
    ):
        provider = plugin.ACMEIssuerPlugin()
        mock_authority = Mock()

        mock_client = Mock()
        mock_acme.return_value = (mock_client, "")

        mock_dns_provider = Mock()
        mock_dns_provider.credentials = '{"account_id": 1}'
        mock_dns_provider.provider_type = "route53"
        mock_dns_provider_service.get.return_value = mock_dns_provider

        issuer_options = {
            "authority": mock_authority,
            "dns_provider": mock_dns_provider,
            "common_name": "test.netflix.net",
        }
        csr = "123"
        mock_request_certificate.return_value = ("pem_certificate", "chain")
        result = provider.create_certificate(csr, issuer_options)
        assert result

    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.start_dns_challenge", return_value="test")
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
        "lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.complete_dns_challenge",
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
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    @patch("lemur.plugins.lemur_acme.acme_handlers.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.request_certificate")
    def test_get_ordered_certificate(
            self,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_dns_provider_service_p,
            mock_dns_provider_service,
            mock_authorization_service,
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
    @patch("lemur.plugins.lemur_acme.plugin.authorization_service")
    @patch("lemur.plugins.lemur_acme.acme_handlers.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.get_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.finalize_authorizations")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeDnsHandler.request_certificate")
    def test_get_ordered_certificates(
            self,
            mock_request_certificate,
            mock_finalize_authorizations,
            mock_get_authorizations,
            mock_dns_provider_service,
            mock_dns_provider_service_p,
            mock_authorization_service,
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
