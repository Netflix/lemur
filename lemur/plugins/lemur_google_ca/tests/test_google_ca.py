import json
import pytest
import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

import arrow
from flask import Flask
import google.cloud.security.privateca_v1 as privateca
from google.protobuf import duration_pb2

from lemur.constants import CRLReason
from lemur.plugins.lemur_google_ca import plugin

_test_config = {
    'GOOGLE_APPLICATION_CREDENTIALS': '123'
}


def config_mock(key):
    return _test_config[key]


class TestGoogleCa(unittest.TestCase):
    def setUp(self):
        _app = Flask('lemur_test_google_ca')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch('lemur.plugins.lemur_google_ca.plugin.create_ca_client')
    def test_fetch_authority_enabled(self, mock_ca_client):
        # Set up mock response
        mock_resp = MagicMock()
        mock_resp.state = privateca.CertificateAuthority.State.ENABLED
        mock_resp.pem_ca_certificates = ['ca_pem_certificate', 'ca_chain_certificate1', 'ca_chain_certificate2']
        mock_ca_client.return_value.get_certificate_authority.return_value = mock_resp

        ca_path = "projects/my-project/locations/my-location/certificateAuthorities/my-ca"
        ca_pem, ca_chain = plugin.fetch_authority(ca_path)
        self.assertEqual(ca_pem, 'ca_pem_certificate')
        self.assertEqual(ca_chain, 'ca_chain_certificate1\nca_chain_certificate2')

    @patch('lemur.plugins.lemur_google_ca.plugin.create_ca_client')
    def test_fetch_authority_not_enabled(self, mock_ca_client):
        # Set up mock response
        mock_resp = MagicMock()
        mock_resp.state = privateca.CertificateAuthority.State.DISABLED
        mock_ca_client.return_value.get_certificate_authority.return_value = mock_resp

        ca_path = "projects/my-project/locations/my-location/certificateAuthorities/my-ca"

        with pytest.raises(Exception) as exc_info:
            plugin.fetch_authority(ca_path)

        self.assertEqual(str(exc_info.value), f"The CA {ca_path} is not enabled")

    @patch('lemur.plugins.lemur_google_ca.plugin.generate_certificate_id')
    @patch('lemur.plugins.lemur_google_ca.plugin.current_app')
    @patch('lemur.plugins.lemur_google_ca.plugin.create_ca_client')
    def test_create_certificate(self, mock_ca_client, mock_current_app, mock_gen_cert_id):
        mock_gen_cert_id.return_value = "dummy_cert_id"
        mock_current_app.config = _test_config

        # Set up mock response from the CA client
        mock_resp = MagicMock()
        mock_resp.pem_certificate = "cert_pem"
        mock_resp.pem_certificate_chain = ["chain_pem1", "chain_pem2"]
        mock_create_certificate = mock_ca_client.return_value.create_certificate
        mock_create_certificate.return_value = mock_resp

        pg = plugin.GoogleCaIssuerPlugin()
        csr = "dummy_csr"
        options = {
            "authority": MagicMock(
                plugin_name="googleca-issuer",
                options=json.dumps([
                    {"name": "Project", "value": "dummy_project"},
                    {"name": "Location", "value": "dummy_location"},
                    {"name": "CAPool", "value": "dummy_capool"},
                    {"name": "CAName", "value": "dummy_caname"},
                ])
            ),
            "common_name": "example.com"
        }
        cert_pem, chain_pem, ext_id = pg.create_certificate(csr, options)
        self.assertEqual(cert_pem, "cert_pem")
        self.assertEqual(chain_pem, "chain_pem1\nchain_pem2")

        expected_ca_path = "projects/dummy_project/locations/dummy_location/caPools/dummy_capool"
        expected_lifetime_seconds = 365 * 24 * 60 * 60  # Assuming 1 year in your get_duration function

        # test that we call client.create_certificate the right way
        mock_create_certificate.assert_called_once_with(
            privateca.CreateCertificateRequest(
                parent=expected_ca_path,
                certificate=privateca.Certificate(
                    pem_csr=csr,
                    lifetime=duration_pb2.Duration(seconds=expected_lifetime_seconds)
                ),
                certificate_id="dummy_cert_id",
                # Assuming generate_certificate_id() generates a unique ID each call
                issuing_certificate_authority_id="dummy_caname"
            )
        )

    @patch('lemur.plugins.lemur_google_ca.plugin.current_app')
    @patch('lemur.plugins.lemur_google_ca.plugin.create_ca_client')
    def test_revoke_certificate(self, mock_ca_client, mock_current_app):
        mock_current_app.config = _test_config

        mock_revoke_certificate = mock_ca_client.return_value.revoke_certificate
        mock_revoke_certificate.return_value = "mock_resp"

        certificate = MagicMock(
            authority=MagicMock(
                plugin_name="googleca-issuer",
                options=json.dumps([
                    {"name": "Project", "value": "dummy_project"},
                    {"name": "Location", "value": "dummy_location"},
                    {"name": "CAPool", "value": "dummy_capool"},
                    {"name": "CAName", "value": "dummy_caname"},
                ])
            ),
            external_id="dummy_external_id",
        )

        pg = plugin.GoogleCaIssuerPlugin()
        resp = pg.revoke_certificate(
            certificate=certificate,
            reason={
                "crl_reason": "unspecified"
            }
        )

        self.assertEqual(resp, "mock_resp")
        mock_revoke_certificate.assert_called_once_with(
            request=privateca.RevokeCertificateRequest(
                name="projects/dummy_project/locations/dummy_location/caPools/dummy_capool/certificates/dummy_external_id",
                reason=CRLReason.unspecified.value,
            )
        )

    @patch("lemur.plugins.lemur_google_ca.plugin.arrow.utcnow")
    def test_get_duration_with_validity_end(self, mock_now):
        mock_now.return_value = arrow.get(2023, 4, 10)
        # Simulate options where validity_end is 10 days from now
        expected_duration = 10 * 24 * 60 * 60  # 10 days in seconds
        ret_duration = plugin.get_duration({
            "validity_end": arrow.get(2023, 4, 20)
        })
        self.assertEqual(ret_duration, expected_duration)

    @patch("lemur.plugins.lemur_google_ca.plugin.arrow.utcnow")
    def test_get_duration_with_validity_years(self, mock_now):
        mock_now.return_value = arrow.get(2023, 4, 10)
        # Simulate options with validity_years set to 2
        expected_duration = 2 * plugin.SECONDS_PER_YEAR
        ret_duration = plugin.get_duration({"validity_years": 2})
        self.assertEqual(ret_duration, expected_duration)

    @patch("lemur.plugins.lemur_google_ca.plugin.arrow.utcnow")
    def test_get_duration_defaults_to_one_year(self, mock_now):
        mock_now.return_value = arrow.get(2023, 4, 10)
        # Simulate options without validity_end or validity_years
        expected_duration = plugin.SECONDS_PER_YEAR  # Default to 1 year
        ret_duration = plugin.get_duration({})
        self.assertEqual(ret_duration, expected_duration)
