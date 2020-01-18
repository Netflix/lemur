import unittest
from requests.models import Response

from mock import MagicMock, Mock, patch

from lemur.plugins.lemur_acme import plugin, powerdns

class TestPowerdns(unittest.TestCase):
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    def setUp(self, mock_dns_provider_service):
        self.ACMEIssuerPlugin = plugin.ACMEIssuerPlugin()
        self.acme = plugin.AcmeHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "powerdns"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "powerdns"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }

    @patch("lemur.plugins.lemur_acme.powerdns.requests")
    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_powerdns_get_token(self, mock_current_app, mock_requests):
        # ret_val = json.dumps({"access_token": "access"})
        the_response = Response()
        the_response._content = b'{"access_token": "access"}'
        mock_requests.post = Mock(return_value=the_response)
        mock_current_app.config.get = Mock(return_value="Test")
        result = powerdns.get_powerdns_token()
        self.assertTrue(len(result) > 0)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_powerdns_create_txt_record(self, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        powerdns.get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        powerdns._post = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "message": "TXT record created"
        }
        result = powerdns.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    @patch("lemur.extensions.metrics")
    def test_powerdns_delete_txt_record(self, mock_metrics, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        mock_current_app.logger.debug = Mock()
        powerdns.get_zone_name = Mock(return_value=zone)
        powerdns._post = Mock()
        powerdns._get = Mock()
        powerdns._get.return_value = {'zoneName': 'test.example.com.com',
                'rrSets': [{'ownerName': '_acme-challenge.test.example.com.',
                            'rrtype': 'TXT (16)', 'ttl': 5, 'rdata': ['ABCDEFGHIJ']}],
                'queryInfo': {'sort': 'OWNER', 'reverse': False, 'limit': 100},
                'resultInfo': {'totalCount': 1, 'offset': 0, 'returnedCount': 1}}
        powerdns._delete = Mock()
        mock_metrics.send = Mock()
        powerdns.delete_txt_record(change_id, account_number, domain, token)
        mock_current_app.logger.debug.assert_not_called()
        mock_metrics.send.assert_not_called()

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    @patch("lemur.extensions.metrics")
    def test_powerdns_wait_for_dns_change(self, mock_metrics, mock_current_app):
        powerdns._has_dns_propagated = Mock(return_value=True)
        nameserver = "1.1.1.1"
        powerdns.get_authoritative_nameserver = Mock(return_value=nameserver)
        mock_metrics.send = Mock()
        domain = "_acme-challenge.test.example.com"
        token = "ABCDEFGHIJ"
        change_id = (domain, token)
        mock_current_app.logger.debug = Mock()
        powerdns.wait_for_dns_change(change_id)
        # mock_metrics.send.assert_not_called()
        log_data = {
            "function": "wait_for_dns_change",
            "fqdn": domain,
            "status": True,
            "message": "Record status on Public DNS"
        }
        mock_current_app.logger.debug.assert_called_with(log_data)

    def test_powerdns_get_zone_name(self):
        zones = ['example.com', 'test.example.com']
        zone = "test.example.com"
        domain = "_acme-challenge.test.example.com"
        account_number = "1234567890"
        powerdns.get_zones = Mock(return_value=zones)
        result = powerdns.get_zone_name(domain, account_number)
        self.assertEqual(result, zone)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_powerdns_get_zones(self, mock_current_app):
        account_number = "1234567890"
        path = "a/b/c"
        zones = ['example.com', 'test.example.com']
        get_response = [{'account': '', 'dnssec': 'False', 'id': 'example.com.', 'kind': 'Master', 'last_check': 0, 'masters': [],
          'name': 'example.com.', 'notified_serial': '2019111907', 'serial': '2019111907',
          'url': '/api/v1/servers/localhost/zones/example.com.'},
         {'account': '', 'dnssec': 'False', 'id': 'bad.example.com.', 'kind': 'Secondary', 'last_check': 0, 'masters': [],
          'name': 'bad.example.com.', 'notified_serial': '2018053104', 'serial': '2018053104',
          'url': '/api/v1/servers/localhost/zones/bad.example.com.'},
         {'account': '', 'dnssec': 'False', 'id': 'test.example.com.', 'kind': 'Master', 'last_check': 0,
          'masters': [], 'name': 'test.example.com.', 'notified_serial': '2019112501', 'serial': '2019112501',
          'url': '/api/v1/servers/localhost/zones/test.example.com.'}]
        powerdns._get = Mock(path)
        powerdns._get.side_effect = [get_response]
        mock_current_app.config.get = Mock(return_value="localhost")
        result = powerdns.get_zones(account_number)
        self.assertEqual(result, zones)