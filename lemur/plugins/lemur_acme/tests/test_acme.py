import unittest

from acme import challenges

from lemur.plugins.lemur_acme import plugin, route53, cloudflare
from lemur.plugins.base import plugins
from mock import MagicMock, Mock, patch


class TestAcme(unittest.TestCase):

    @patch('lemur.plugins.lemur_acme.plugin.len', return_value=1)
    def test_find_dns_challenge(self, mock_len):
        assert mock_len

        from acme import challenges
        c = challenges.DNS01()

        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = Mock()
        mock_entry.chall = c
        mock_authz.body.resolved_combinations.append(mock_entry)
        result = yield plugin.find_dns_challenge(mock_authz)
        self.assertEqual(result, mock_entry)

    def test_authz_record(self):
        a = plugin.AuthorizationRecord("host", "authz", "challenge", "id")
        self.assertEqual(type(a), plugin.AuthorizationRecord)

    @patch('acme.client.Client')
    @patch('lemur.plugins.lemur_acme.plugin.current_app')
    @patch('lemur.plugins.lemur_acme.plugin.len', return_value=1)
    @patch('lemur.plugins.lemur_acme.plugin.find_dns_challenge')
    def test_start_dns_challenge(self, mock_find_dns_challenge, mock_len, mock_app, mock_acme):
        assert mock_len
        mock_app.logger.debug = Mock()
        mock_authz = Mock()
        mock_authz.body.resolved_combinations = []
        mock_entry = MagicMock()
        from acme import challenges
        c = challenges.DNS01()
        mock_entry.chall = c
        mock_authz.body.resolved_combinations.append(mock_entry)
        mock_acme.request_domain_challenges = Mock(return_value=mock_authz)
        mock_dns_provider = Mock()
        mock_dns_provider.create_txt_record = Mock(return_value=1)

        values = [mock_entry]
        iterable = mock_find_dns_challenge.return_value
        iterator = iter(values)
        iterable.__iter__.return_value = iterator
        result = plugin.start_dns_challenge(mock_acme, "accountid", "host", mock_dns_provider)
        self.assertEqual(type(result), plugin.AuthorizationRecord)

    @patch('acme.client.Client')
    def test_complete_dns_challenge_success(self, mock_acme):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)

        mock_authz = Mock()
        mock_authz.dns_challenge.response = Mock()
        mock_authz.dns_challenge.response.simple_verify = Mock(return_value=True)

        plugin.complete_dns_challenge(mock_acme, "accountid", mock_authz, mock_dns_provider)

    @patch('acme.client.Client')
    def test_complete_dns_challenge_fail(self, mock_acme):
        mock_dns_provider = Mock()
        mock_dns_provider.wait_for_dns_change = Mock(return_value=True)

        mock_authz = Mock()
        mock_authz.dns_challenge.response = Mock()
        mock_authz.dns_challenge.response.simple_verify = Mock(return_value=False)
        self.assertRaises(
            ValueError,
            plugin.complete_dns_challenge(mock_acme, "accountid", mock_authz, mock_dns_provider)
        )

    @patch('acme.client.Client')
    @patch('OpenSSL.crypto', return_value="mock_cert")
    @patch('josepy.util.ComparableX509')
    @patch('lemur.plugins.lemur_acme.plugin.find_dns_challenge')
    @patch('lemur.plugins.lemur_acme.plugin.current_app')
    def test_request_certificate(self, mock_current_app, mock_find_dns_challenge, mock_jose, mock_crypto, mock_acme):
        mock_cert_response = Mock()
        mock_cert_response.body = "123"
        mock_cert_response_full = [mock_cert_response, True]
        mock_acme.poll_and_request_issuance = Mock(return_value=mock_cert_response_full)
        mock_authz = []
        mock_authz_record = MagicMock()
        mock_authz_record.authz = Mock()
        mock_authz.append(mock_authz_record)
        mock_acme.fetch_chain = Mock(return_value="mock_chain")
        mock_crypto.dump_certificate = Mock(return_value=b'chain')

        plugin.request_certificate(mock_acme, [], "mock_csr")

    def test_setup_acme_client_fail(self):
        mock_authority = Mock()
        mock_authority.options = []
        with self.assertRaises(Exception):
            plugin.setup_acme_client(mock_authority)

    @patch('lemur.plugins.lemur_acme.plugin.Client')
    @patch('lemur.plugins.lemur_acme.plugin.current_app')
    def test_setup_acme_client_success(self, mock_current_app, mock_acme):
        mock_authority = Mock()
        mock_authority.options = '{"o": "mock_name", "v": "mock_value"}'
        mock_client = Mock()
        mock_registration = Mock()
        mock_registration.uri = "http://test.com"
        mock_client.register = mock_registration
        mock_client.agree_to_tos = Mock(return_value=True)
        mock_acme.return_value = mock_client
        result_client, result_registration = plugin.setup_acme_client(mock_authority)
        assert result_client
        assert result_registration

