import arrow
import json
from unittest import TestCase
from flask import Flask
from lemur.plugins.lemur_sectigo.plugin import (
    SectigoIssuerPlugin,
    _determine_certificate_term,
)
from lemur.tests.vectors import (
    ROOTCA_CERT_STR,
    INTERMEDIATE_CERT_STR,
    WILDCARD_CERT_STR,
)
import requests_mock


class TestSectigoIssuerPlugin(TestCase):
    def setUp(self):
        # Creates a new Flask application for a test duration.
        _app = Flask(__name__)
        self.app_context = _app.app_context()
        assert self.app_context
        self.app_context.push()
        _app.config = {
            "DEBUG": True,
            "SECTIGO_BASE_URL": "mock://cert-manager.com/api",
            "SECTIGO_LOGIN_URI": "lemur",
            "SECTIGO_USERNAME": "lemur@test.com",
            "SECTIGO_PASSWORD": "test1234",
            "SECTIGO_ORG_NAME": "Lemur, Inc.",
            "SECTIGO_CERT_TYPE": "SectigoSSL UCC DV",
            "SECTIGO_ROOT": "fakeroot",
        }

    def tearDown(self):
        self.app_context.pop()

    def test_create_certificate(self):
        with self.app_context:
            plugin = SectigoIssuerPlugin()

            adapter = requests_mock.Adapter()
            adapter.register_uri(
                "GET",
                "mock://cert-manager.com/api/organization/v1",
                text=json.dumps(
                    [{"id": 1000, "name": "Lemur, Inc.", "departments": []}]
                ),
            )
            adapter.register_uri(
                "GET",
                "mock://cert-manager.com/api/ssl/v1/types",
                text=json.dumps(
                    [
                        {
                            "id": 2000,
                            "name": "SectigoSSL UCC DV",
                            "description": "Fake description",
                            "terms": [365, 30],
                            "keyTypes": {"RSA": ["2048"]},
                            "useSecondaryOrgName": False,
                        }
                    ]
                ),
            )
            adapter.register_uri(
                "POST",
                "mock://cert-manager.com/api/ssl/v1/enroll",
                text=json.dumps(
                    {
                        "sslId": 3000,
                        "renewId": "4Wlit-fvmmk3bTcZz3D8",
                    }
                ),
            )
            adapter.register_uri(
                "GET",
                "mock://cert-manager.com/api/ssl/v1/collect/3000/pem",
                text=ROOTCA_CERT_STR + INTERMEDIATE_CERT_STR + WILDCARD_CERT_STR,
            )
            adapter.register_uri(
                "GET",
                "mock://cert-manager.com/api/ssl/v1/customFields",
                text=json.dumps([]),
            )
            plugin.client.session.mount("mock", adapter)

            with self.subTest(case="create certificate with supported term"):
                cert_pem, ca_bundle, cert_id = plugin.create_certificate(
                    "",
                    {
                        "common_name": "star.wild.example.org",
                        "validity_end": arrow.utcnow().shift(days=30),
                    },
                )
                assert WILDCARD_CERT_STR == cert_pem
                assert (INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR) == ca_bundle
                assert 3000 == cert_id

            with self.subTest(case="create certificates with unsupported terms"):
                cert_pem, ca_bundle, cert_id = plugin.create_certificate(
                    "",
                    {
                        "common_name": "star.wild.example.org",
                        "validity_end": arrow.utcnow().shift(days=72),
                    },
                )
                assert WILDCARD_CERT_STR == cert_pem
                assert (INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR) == ca_bundle
                assert 3000 == cert_id

                cert_pem, ca_bundle, cert_id = plugin.create_certificate(
                    "",
                    {
                        "common_name": "star.wild.example.org",
                        "validity_end": arrow.utcnow().shift(days=365 * 5),
                    },
                )
                assert WILDCARD_CERT_STR == cert_pem
                assert (INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR) == ca_bundle
                assert 3000 == cert_id

                cert_pem, ca_bundle, cert_id = plugin.create_certificate(
                    "",
                    {
                        "common_name": "star.wild.example.org",
                        "validity_end": arrow.utcnow().shift(days=180),
                    },
                )
                assert WILDCARD_CERT_STR == cert_pem
                assert (INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR) == ca_bundle
                assert 3000 == cert_id

    def test_determine_certificate_term(self):
        with self.app_context:
            assert 365 == _determine_certificate_term(
                arrow.utcnow().shift(days=365 * 5), [30, 365]
            )
            assert 365 == _determine_certificate_term(
                arrow.utcnow().shift(days=270), [30, 365]
            )
            assert 365 == _determine_certificate_term(
                arrow.utcnow().shift(days=365), [365]
            )
            assert 365 == _determine_certificate_term(
                arrow.utcnow().shift(days=397), [365]
            )
            assert 30 == _determine_certificate_term(
                arrow.utcnow().shift(days=72), [30, 365]
            )
            assert 30 == _determine_certificate_term(
                arrow.utcnow().shift(days=30), [30, 365]
            )
            assert 30 == _determine_certificate_term(
                arrow.utcnow().shift(days=30), [30]
            )
            assert 30 == _determine_certificate_term(
                arrow.utcnow().shift(days=90), [30]
            )
