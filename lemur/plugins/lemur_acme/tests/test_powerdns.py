import unittest
from unittest.mock import patch, Mock

from flask import Flask
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

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_acme')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_get_zones(self, mock_current_app):
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
        powerdns._check_conf = Mock()
        powerdns._get = Mock(path)
        powerdns._get.side_effect = [get_response]
        mock_current_app.config.get = Mock(return_value="localhost")
        result = powerdns.get_zones(account_number)
        self.assertEqual(result, zones)

    def test_get_zone_name(self):
        zones = ['example.com', 'test.example.com']
        zone = "test.example.com"
        domain = "_acme-challenge.test.example.com"
        account_number = "1234567890"
        powerdns.get_zones = Mock(return_value=zones)
        result = powerdns._get_zone_name(domain, account_number)
        self.assertEqual(result, zone)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_create_txt_record_write_only(self, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        powerdns._check_conf = Mock()
        powerdns._get_txt_records = Mock(return_value=[])
        powerdns._get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        powerdns._patch = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "message": "TXT record(s) successfully created"
        }
        result = powerdns.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_create_txt_record_append(self, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        powerdns._check_conf = Mock()
        cur_token = "123456"
        cur_records = [powerdns.Record({'name': domain, 'content': f"\"{cur_token}\"", 'disabled': False})]
        powerdns._get_txt_records = Mock(return_value=cur_records)
        powerdns._get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        powerdns._patch = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "message": "TXT record(s) successfully created"
        }
        expected_path = "/api/v1/servers/localhost/zones/test.example.com."
        expected_payload = {
            "rrsets": [
                {
                    "name": domain + ".",
                    "type": "TXT",
                    "ttl": 300,
                    "changetype": "REPLACE",
                    "records": [
                        {
                            "content": f"\"{token}\"",
                            "disabled": False
                        },
                        {
                            "content": f"\"{cur_token}\"",
                            "disabled": False
                        }
                    ],
                    "comments": []
                }
            ]
        }

        result = powerdns.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        powerdns._patch.assert_called_with(expected_path, expected_payload)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.powerdns.dnsutil")
    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    @patch("lemur.extensions.metrics")
    @patch("time.sleep")
    def test_wait_for_dns_change(self, mock_sleep, mock_metrics, mock_current_app, mock_dnsutil):
        domain = "_acme-challenge.test.example.com"
        token1 = "ABCDEFG"
        token2 = "HIJKLMN"
        zone_name = "test.example.com"
        nameserver = "1.1.1.1"
        change_id = (domain, token1)
        powerdns._check_conf = Mock()
        mock_records = (token2, token1)
        mock_current_app.config.get = Mock(return_value=1)
        powerdns._get_zone_name = Mock(return_value=zone_name)
        mock_dnsutil.get_authoritative_nameserver = Mock(return_value=nameserver)
        mock_dnsutil.get_dns_records = Mock(return_value=mock_records)
        mock_sleep.return_value = False
        mock_metrics.send = Mock()
        mock_current_app.logger.debug = Mock()
        powerdns.wait_for_dns_change(change_id)

        log_data = {
            "function": "wait_for_dns_change",
            "fqdn": domain,
            "status": True,
            "message": "Record status on PowerDNS authoritative server"
        }
        mock_current_app.logger.debug.assert_called_with(log_data)

    @patch("lemur.plugins.lemur_acme.powerdns.current_app")
    def test_delete_txt_record(self, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        powerdns._check_conf = Mock()
        powerdns._get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        powerdns._patch = Mock()
        log_data = {
            "function": "delete_txt_record",
            "fqdn": domain,
            "token": token,
            "message": "Unable to delete TXT record: Token not found in existing TXT records"
        }
        powerdns.delete_txt_record(change_id, account_number, domain, token)
        mock_current_app.logger.debug.assert_called_with(log_data)
