import unittest
from unittest.mock import patch, Mock

from flask import Flask
from lemur.plugins.lemur_acme import plugin, ultradns
from requests.models import Response


class TestUltradns(unittest.TestCase):
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

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask("lemur_test_acme")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("lemur.plugins.lemur_acme.ultradns.requests")
    @patch("lemur.plugins.lemur_acme.ultradns.current_app")
    def test_ultradns_get_token(self, mock_current_app, mock_requests):
        # ret_val = json.dumps({"access_token": "access"})
        the_response = Response()
        the_response._content = b'{"access_token": "access"}'
        mock_requests.post = Mock(return_value=the_response)
        mock_current_app.config.get = Mock(return_value="Test")
        result = ultradns.get_ultradns_token()
        self.assertTrue(len(result) > 0)

    @patch("lemur.plugins.lemur_acme.ultradns.current_app")
    def test_ultradns_create_txt_record(self, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        ultradns.get_zone_name = Mock(return_value=zone)
        mock_current_app.logger.debug = Mock()
        ultradns._post = Mock()
        log_data = {
            "function": "create_txt_record",
            "fqdn": domain,
            "token": token,
            "message": "TXT record created",
        }
        result = ultradns.create_txt_record(domain, token, account_number)
        mock_current_app.logger.debug.assert_called_with(log_data)
        self.assertEqual(result, change_id)

    @patch("lemur.plugins.lemur_acme.ultradns.current_app")
    @patch("lemur.extensions.metrics")
    def test_ultradns_delete_txt_record(self, mock_metrics, mock_current_app):
        domain = "_acme_challenge.test.example.com"
        zone = "test.example.com"
        token = "ABCDEFGHIJ"
        account_number = "1234567890"
        change_id = (domain, token)
        mock_current_app.logger.debug = Mock()
        ultradns.get_zone_name = Mock(return_value=zone)
        ultradns._post = Mock()
        ultradns._get = Mock()
        ultradns._get.return_value = {
            "zoneName": "test.example.com.com",
            "rrSets": [
                {
                    "ownerName": "_acme-challenge.test.example.com.",
                    "rrtype": "TXT (16)",
                    "ttl": 5,
                    "rdata": ["ABCDEFGHIJ"],
                }
            ],
            "queryInfo": {"sort": "OWNER", "reverse": False, "limit": 100},
            "resultInfo": {"totalCount": 1, "offset": 0, "returnedCount": 1},
        }
        ultradns._delete = Mock()
        mock_metrics.send = Mock()
        ultradns.delete_txt_record(change_id, account_number, domain, token)
        mock_current_app.logger.debug.assert_not_called()
        mock_metrics.send.assert_not_called()

    @patch("lemur.plugins.lemur_acme.ultradns.current_app")
    @patch("lemur.extensions.metrics")
    def test_ultradns_wait_for_dns_change(self, mock_metrics, mock_current_app):
        ultradns._has_dns_propagated = Mock(return_value=True)
        nameserver = "1.1.1.1"
        ultradns.get_authoritative_nameserver = Mock(return_value=nameserver)
        mock_metrics.send = Mock()
        domain = "_acme-challenge.test.example.com"
        token = "ABCDEFGHIJ"
        change_id = (domain, token)
        mock_current_app.logger.debug = Mock()
        ultradns.wait_for_dns_change(change_id)
        # mock_metrics.send.assert_not_called()
        log_data = {
            "function": "wait_for_dns_change",
            "fqdn": domain,
            "status": True,
            "message": "Record status on Public DNS",
        }
        mock_current_app.logger.debug.assert_called_with(log_data)

    def test_ultradns_get_zone_name(self):
        zones = ["example.com", "test.example.com"]
        zone = "test.example.com"
        domain = "_acme-challenge.test.example.com"
        account_number = "1234567890"
        ultradns.get_zones = Mock(return_value=zones)
        result = ultradns.get_zone_name(domain, account_number)
        self.assertEqual(result, zone)

    def test_ultradns_get_zones(self):
        account_number = "1234567890"
        path = "a/b/c"
        zones = ["example.com", "test.example.com"]
        paginate_response = [
            {
                "properties": {
                    "name": "example.com.",
                    "accountName": "example",
                    "type": "PRIMARY",
                    "dnssecStatus": "UNSIGNED",
                    "status": "ACTIVE",
                    "resourceRecordCount": 9,
                    "lastModifiedDateTime": "2017-06-14T06:45Z",
                },
                "registrarInfo": {
                    "nameServers": {
                        "missing": [
                            "example.ultradns.com.",
                            "example.ultradns.net.",
                            "example.ultradns.biz.",
                            "example.ultradns.org.",
                        ]
                    }
                },
                "inherit": "ALL",
            },
            {
                "properties": {
                    "name": "test.example.com.",
                    "accountName": "example",
                    "type": "PRIMARY",
                    "dnssecStatus": "UNSIGNED",
                    "status": "ACTIVE",
                    "resourceRecordCount": 9,
                    "lastModifiedDateTime": "2017-06-14T06:45Z",
                },
                "registrarInfo": {
                    "nameServers": {
                        "missing": [
                            "example.ultradns.com.",
                            "example.ultradns.net.",
                            "example.ultradns.biz.",
                            "example.ultradns.org.",
                        ]
                    }
                },
                "inherit": "ALL",
            },
            {
                "properties": {
                    "name": "example2.com.",
                    "accountName": "example",
                    "type": "SECONDARY",
                    "dnssecStatus": "UNSIGNED",
                    "status": "ACTIVE",
                    "resourceRecordCount": 9,
                    "lastModifiedDateTime": "2017-06-14T06:45Z",
                },
                "registrarInfo": {
                    "nameServers": {
                        "missing": [
                            "example.ultradns.com.",
                            "example.ultradns.net.",
                            "example.ultradns.biz.",
                            "example.ultradns.org.",
                        ]
                    }
                },
                "inherit": "ALL",
            },
        ]
        ultradns._paginate = Mock(path, "zones")
        ultradns._paginate.side_effect = [[paginate_response]]
        result = ultradns.get_zones(account_number)
        self.assertEqual(result, zones)
