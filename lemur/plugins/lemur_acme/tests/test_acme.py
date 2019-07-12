import unittest

from mock import MagicMock, Mock, patch

from lemur.plugins.lemur_acme import plugin


class TestAcme(unittest.TestCase):
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    def setUp(self, mock_dns_provider_service):
        self.ACMEIssuerPlugin = plugin.ACMEIssuerPlugin()
        self.acme = plugin.AcmeHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "cloudflare"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "cloudflare"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }

    @patch("lemur.plugins.lemur_acme.plugin.len", return_value=1)
    def test_find_dns_challenge(self, mock_len):
        assert mock_len

        from acme import challenges

        c = challenges.DNS01()

        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = Mock()
        mock_entry.chall = c
        mock_authz.body.resolved_combinations.append(mock_entry)
        result = yield self.acme.find_dns_challenge(mock_authz)
        self.assertEqual(result, mock_entry)

    def test_authz_record(self):
        a = plugin.AuthorizationRecord("host", "authz", "challenge", "id")
        self.assertEqual(type(a), plugin.AuthorizationRecord)

    @patch("acme.client.Client")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.len", return_value=1)
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.find_dns_challenge")
    def test_start_dns_challenge(
        self, mock_find_dns_challenge, mock_len, mock_app, mock_acme
    ):
        assert mock_len
        mock_order = Mock()
        mock_app.logger.debug = Mock()
        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = MagicMock()
        from acme import challenges

        c = challenges.DNS01()
        mock_entry.chall = TestAcme.test_complete_dns_challenge_fail
        mock_authz.body.resolved_combinations.append(mock_entry)
        mock_acme.request_domain_challenges = Mock(return_value=mock_authz)
        mock_dns_provider = Mock()
        mock_dns_provider.create_txt_record = Mock(return_value=1)

        values = [mock_entry]
        iterable = mock_find_dns_challenge.return_value
        iterator = iter(values)
        iterable.__iter__.return_value = iterator
        result = self.acme.start_dns_challenge(
            mock_acme, "accountid", "host", mock_dns_provider, mock_order, {}
        )
        self.assertEqual(type(result), plugin.AuthorizationRecord)

    @patch("acme.client.Client")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.cloudflare.wait_for_dns_change")
    def test_complete_dns_challenge_success(
        self, mock_wait_for_dns_change, mock_current_app, mock_acme
    ):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)
        mock_authz = Mock()
        mock_authz.dns_challenge.response = Mock()
        mock_authz.dns_challenge.response.simple_verify = Mock(return_value=True)
        mock_authz.authz = []
        mock_authz.host = "www.test.com"
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
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.cloudflare.wait_for_dns_change")
    def test_complete_dns_challenge_fail(
        self, mock_wait_for_dns_change, mock_current_app, mock_acme
    ):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)

        mock_authz = Mock()
        mock_authz.dns_challenge.response = Mock()
        mock_authz.dns_challenge.response.simple_verify = Mock(return_value=False)
        mock_authz.authz = []
        mock_authz.host = "www.test.com"
        mock_authz_record = Mock()
        mock_authz_record.body.identifier.value = "test"
        mock_authz.authz.append(mock_authz_record)
        mock_authz.change_id = []
        mock_authz.change_id.append("123")
        mock_authz.dns_challenge = []
        dns_challenge = Mock()
        mock_authz.dns_challenge.append(dns_challenge)
        self.assertRaises(
            ValueError, self.acme.complete_dns_challenge(mock_acme, mock_authz)
        )

    @patch("acme.client.Client")
    @patch("OpenSSL.crypto", return_value="mock_cert")
    @patch("josepy.util.ComparableX509")
    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.find_dns_challenge")
    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_request_certificate(
        self,
        mock_current_app,
        mock_find_dns_challenge,
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

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_get_domains_single(self, mock_current_app):
        options = {"common_name": "test.netflix.net"}
        result = self.acme.get_domains(options)
        self.assertEqual(result, [options["common_name"]])

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_get_domains_multiple(self, mock_current_app):
        options = {
            "common_name": "test.netflix.net",
            "extensions": {
                "sub_alt_names": {"names": ["test2.netflix.net", "test3.netflix.net"]}
            },
        }
        result = self.acme.get_domains(options)
        self.assertEqual(
            result, [options["common_name"], "test2.netflix.net", "test3.netflix.net"]
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

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    def test_create_authority(self, mock_current_app):
        mock_current_app.config = Mock()
        options = {
            "plugin": {"plugin_options": [{"name": "certificate", "value": "123"}]}
        }
        acme_root, b, role = self.ACMEIssuerPlugin.create_authority(options)
        self.assertEqual(acme_root, "123")
        self.assertEqual(b, "")
        self.assertEqual(role, [{"username": "", "password": "", "name": "acme"}])

    @patch("lemur.plugins.lemur_acme.plugin.current_app")
    @patch("lemur.plugins.lemur_acme.dyn.current_app")
    @patch("lemur.plugins.lemur_acme.cloudflare.current_app")
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    def test_get_dns_provider(
        self,
        mock_dns_provider_service,
        mock_current_app_cloudflare,
        mock_current_app_dyn,
        mock_current_app,
    ):
        provider = plugin.ACMEIssuerPlugin()
        route53 = provider.get_dns_provider("route53")
        assert route53
        cloudflare = provider.get_dns_provider("cloudflare")
        assert cloudflare
        dyn = provider.get_dns_provider("dyn")
        assert dyn

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

    @patch("lemur.plugins.lemur_acme.plugin.AcmeHandler.setup_acme_client")
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
