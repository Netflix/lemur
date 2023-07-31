"""
Unit Tests for NSone DNS provider
"""
import unittest
from unittest.mock import patch, Mock

from flask import Flask

from lemur.plugins.lemur_acme import plugin, nsone


class TestNsone(unittest.TestCase):
    """
    Class for testing NSone plugin
    """
    @patch("lemur.plugins.lemur_acme.plugin.dns_provider_service")
    def setUp(self, mock_dns_provider_service):
        """
        unittest setup
        """
        self.ACMEIssuerPlugin = plugin.ACMEIssuerPlugin()
        self.acme = plugin.AcmeHandler()
        mock_dns_provider = Mock()
        mock_dns_provider.name = "nsone"
        mock_dns_provider.credentials = "{}"
        mock_dns_provider.provider_type = "nsone"
        self.acme.dns_providers_for_domain = {
            "www.test.com": [mock_dns_provider],
            "test.fakedomain.net": [mock_dns_provider],
        }

        # Creates a new Flask application for a test duration. In python 3.8,
        # manual push of application context is needed to run tests in dev environment
        # without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_acme')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("lemur.plugins.lemur_acme.nsone.current_app")
    def test_get_zones(self, mock_current_app):
        """
        Testing get_zones method
        """
        account_number = "1234567890"
        path = "a/b/c"
        zones = ['example.com', 'test.example.com']
        get_response = [{
            "dns_servers": ["string"],
            "expiry": 0,
            "primary_master": "string",
            "id": "string",
            "meta": {
                "asn": ["string"],
                "ca_province": ["string"],
                "connections": 0,
                "country": ["string"],
                "georegion": ["string"],
                "high_watermark": 0,
                "ip_prefixes": ["string"],
                "latitude": 0,
                "loadAvg": 0,
                "laditude": 0,
                "low_watermark": 0,
                "note": "string",
                "priority": 0,
                "pulsar": "string",
                "requests": 0,
                "up": True,
                "us_state": ["string"],
                "weight": 0
            },
            "network_pools": ["string"],
            "networks": [0],
            "nx_ttl": 0,
            "primary": {
                "enabled": True,
                "secondaries": [{
                    "ip": "string",
                    "networks": [0],
                    "notify": True,
                    "port": 0}]
            }, "records": [{
                "domain": "string",
                "id": "string",
                "short_answers": ["string"],
                "tier": 0,
                "ttl": 0,
                "type": "string"}],
            "refresh": 0,
            "retry": 0,
            "ttl": 0,
            "zone": "string",
            "view": ["string"],
            "local_tags": ["string"],
            "tags": {}}]
        nsone._check_conf = Mock()
        nsone._get = Mock(path)
        nsone._get.side_effect = [get_response]
        mock_current_app.config.get = Mock(return_value="localhost")
        result = nsone.get_zones(account_number)
        self.assertEqual(result, zones)

    def test_get_zone_name(self):
        """
        Testing get_zone_name method
        """
        zones = ['example.com', 'test.example.com']
        zone = "test.example.com"
        domain = "_acme-challenge.test.example.com"
        account_number = "1234567890"
        nsone.get_zones = Mock(return_value=zones)
        result = nsone._get_zone_name(domain, account_number)
        self.assertEqual(result, zone)

    @patch("lemur.plugins.lemur_acme.nsone.current_app")
    def test_create_txt_record_write_only(self, mock_current_app):
        """
        Testing create_txt_record without any existing data
        """
        domain = "_acme_challenge.test.example.com"
        zone = "example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        nsone._check_conf = Mock()
        nsone._get_txt_records = Mock(return_value={"answers": []})
        nsone._get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        nsone._put = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "account": account_number,
            "records": {"answers": [{"answer": [token]}]},
            "message": "TXT record(s) successfully created"
        }
        result = nsone.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.nsone.current_app")
    def test_create_txt_record_append(self, mock_current_app):
        """
        Testing the create_txt_record with existing answers
        """
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        nsone._check_conf = Mock()
        cur_records = {
            "answers": [{
                "answer": ["ABCDEFHG"],
                "id": "1234567890abcdef"
            }],
            "id": "1234567890abcdef"}
        nsone._get_txt_records = Mock(return_value=cur_records)
        nsone._get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        nsone._patch = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "account": account_number,
            "records": cur_records,
            "message": "TXT record(s) successfully created"
        }
        expected_path = "/v1/zones/test.example.com/_acme_challenge.test.example.com/TXT"
        expected_payload = {
            "answers": [
                {"answer": ["ABCDEFHG"], "id": "1234567890abcdef"},
                {"answer": ["ABCDEFGHIJ"]}
            ],
            "id": "1234567890abcdef"}
        result = nsone.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        nsone._patch.assert_called_with(expected_path, expected_payload)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.nsone.dnsutil")
    @patch("lemur.plugins.lemur_acme.nsone.current_app")
    @patch("lemur.extensions.metrics")
    @patch("time.sleep")
    def test_wait_for_dns_change(self, mock_sleep, mock_metrics, mock_current_app, mock_dnsutil):
        """
        Testing the wait_for_dns_change method
        """
        domain = "_acme-challenge.test.example.com"
        token1 = "ABCDEFG"
        token2 = "HIJKLMN"
        zone_name = "test.example.com"
        nameserver = "1.1.1.1"
        change_id = (domain, token1)
        nsone._check_conf = Mock()
        mock_records = (token2, token1)
        mock_current_app.config.get = Mock(return_value=1)
        nsone._get_zone_name = Mock(return_value=zone_name)
        mock_dnsutil.get_authoritative_nameserver = Mock(return_value=nameserver)
        mock_dnsutil.get_dns_records = Mock(return_value=mock_records)
        mock_sleep.return_value = False
        mock_metrics.send = Mock()
        mock_current_app.logger.debug = Mock()
        nsone.wait_for_dns_change(change_id)

        log_data = {
            "function": "wait_for_dns_change",
            "fqdn": domain,
            "status": True,
            "account": None,
            "message": "Record status on NS1 authoritative server"
        }
        mock_current_app.logger.debug.assert_called_with(log_data)

    @patch("lemur.plugins.lemur_acme.nsone.current_app")
    def test_delete_txt_record(self, mock_current_app):
        """
        Testing the delete_txt_record method.
        """
        domain = "_acme-challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        records = {
            "answers": [{
                "answer": ["ABCDEFG"],
                "id": "1234567890abcdef"
            }],
            "domain": "_acme-challenge.test.example.com",
            "id": "1234567890abcdef",
            "meta": {},
            "networks": [1],
            "regions": {},
            "tags": {},
            "tier": 1,
            "ttl": 3600,
            "type": "TXT",
            "zone_fqdn": "example.com",
            "zone_handle": "example.com",
            "use_client_subnet": "false"
        }
        nsone._check_conf = Mock()
        nsone._get_zone_name = Mock(return_value=zone)
        nsone._get_txt_records = Mock(return_value=records)
        nsone._delete = Mock(return_value="")
        mock_current_app.logger.debug = Mock()
        mock_current_app.config.get = Mock(return_value="localhost")
        nsone._patch = Mock()
        log_data = {
            "function": "delete_txt_record",
            "fqdn": domain,
            "token": token,
            "change": ("_acme-challenge.test.example.com", "ABCDEFGHIJ"),
            "account": "1234567890",
            "message": "Unable to delete TXT record: Token not found in existing TXT records"
        }
        nsone.delete_txt_record(change_id, account_number, domain, token)
        mock_current_app.logger.debug.assert_called_with(log_data)
