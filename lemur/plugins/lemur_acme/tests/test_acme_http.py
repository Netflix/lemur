import unittest
from unittest.mock import patch, Mock

from flask import Flask
from acme import challenges
from lemur.plugins.lemur_acme import plugin


class TestAcmeHttp(unittest.TestCase):

    def setUp(self):
        self.ACMEHttpIssuerPlugin = plugin.ACMEHttpIssuerPlugin()
        self.acme = plugin.AcmeHandler()

        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_acme')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_create_authority(self):
        options = {
            "plugin": {"plugin_options": [{"name": "certificate", "value": "123"}]}
        }
        acme_root, b, role = self.ACMEHttpIssuerPlugin.create_authority(options)
        self.assertEqual(acme_root, "123")
        self.assertEqual(b, "")
        self.assertEqual(role, [{"username": "", "password": "", "name": "acme"}])

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
        mock_authority.options = '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].response_and_validation.return_value = (Mock(), "Anything-goes")
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.HTTP01(
            token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

        mock_client = Mock()
        mock_client.new_order.return_value = mock_order_resource
        mock_client.answer_challenge.return_value = True

        mock_finalized_order = Mock()
        mock_finalized_order.fullchain_pem = "-----BEGIN CERTIFICATE-----\nMIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw\nGjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2\nMDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0\n8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym\noLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0\nZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN\nxDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56\ndhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9\nAgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw\nHQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0\nBggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu\nY3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq\nhkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF\nUGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9\nAFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp\nDQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7\nIkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf\nzWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI\nPTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w\nSVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em\n2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0\nWzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt\nn5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw\nGjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2\nMDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0\n8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym\noLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0\nZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN\nxDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56\ndhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9\nAgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw\nHQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0\nBggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu\nY3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq\nhkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF\nUGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9\nAFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp\nDQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7\nIkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf\nzWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI\nPTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w\nSVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em\n2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0\nWzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt\nn5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=\n-----END CERTIFICATE-----\n"
        mock_client.poll_and_finalize.return_value = mock_finalized_order

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
        pem_certificate, pem_certificate_chain, _ = provider.create_certificate(csr, issuer_options)

        self.assertEqual(pem_certificate, "-----BEGIN CERTIFICATE-----\nMIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw\nGjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2\nMDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0\n8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym\noLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0\nZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN\nxDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56\ndhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9\nAgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw\nHQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0\nBggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu\nY3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq\nhkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF\nUGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9\nAFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp\nDQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7\nIkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf\nzWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI\nPTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w\nSVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em\n2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0\nWzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt\nn5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=\n-----END CERTIFICATE-----\n")
        self.assertEqual(pem_certificate_chain,
                         "-----BEGIN CERTIFICATE-----\nMIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw\nGjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2\nMDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0\n8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym\noLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0\nZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN\nxDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56\ndhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9\nAgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw\nHQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0\nBggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu\nb3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu\nY3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq\nhkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF\nUGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9\nAFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp\nDQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7\nIkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf\nzWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI\nPTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w\nSVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em\n2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0\nWzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt\nn5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=\n-----END CERTIFICATE-----\n")

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
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.HTTP01(
            token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

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
        mock_authority.options = '[{"name": "tokenDestination", "value": "mock-sftp-destination"}]'

        mock_order_resource = Mock()
        mock_order_resource.authorizations = [Mock()]
        mock_order_resource.authorizations[0].body.challenges = [Mock()]
        mock_order_resource.authorizations[0].body.challenges[0].chall = challenges.DNS01(
            token=b'\x0f\x1c\xbe#od\xd1\x9c\xa6j\\\xa4\r\xed\xe5\xbf0pz\xeaxnl)\xea[i\xbc\x95\x08\x96\x1f')

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
