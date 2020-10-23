import json
from unittest.mock import patch, Mock

import arrow
import pytest
from cryptography import x509
from freezegun import freeze_time
from lemur.plugins.lemur_digicert import plugin
from lemur.tests.vectors import CSR_STR


def config_mock(*args):
    values = {
        "DIGICERT_ORG_ID": 111111,
        "DIGICERT_PRIVATE": False,
        "DIGICERT_DEFAULT_SIGNING_ALGORITHM": "sha256",
        "DIGICERT_CIS_PROFILE_NAMES": {"digicert": 'digicert'},
        "DIGICERT_CIS_SIGNING_ALGORITHMS": {"digicert": 'digicert'},
    }
    return values[args[0]]


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_determine_validity_years(mock_current_app):
    assert plugin.determine_validity_years(1) == 1
    assert plugin.determine_validity_years(0) == 1
    assert plugin.determine_validity_years(3) == 1


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_determine_end_date(mock_current_app):
    mock_current_app.config.get = Mock(return_value=397)  # 397 days validity
    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(0)  # 397 days from (2016, 11, 3)
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(arrow.get(2017, 12, 5))
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(arrow.get(2020, 5, 7))


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_fields_with_validity_years(mock_current_app):
    mock_current_app.config.get = Mock(side_effect=config_mock)

    with patch('lemur.plugins.lemur_digicert.plugin.signature_hash') as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = [u"one.example.com", u"two.example.com", u"three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
            "validity_years": 1
        }
        expected = {
            "certificate": {
                "csr": CSR_STR,
                "common_name": "example.com",
                "dns_names": names,
                "signature_hash": "sha256",
            },
            "organization": {"id": 111111},
            "validity_years": 1,
        }
        assert expected == plugin.map_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_fields_with_validity_end_and_start(mock_current_app):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 5, 7))

    with patch('lemur.plugins.lemur_digicert.plugin.signature_hash') as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = [u"one.example.com", u"two.example.com", u"three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
            "validity_end": arrow.get(2017, 5, 7),
            "validity_start": arrow.get(2016, 10, 30),
        }

        expected = {
            "certificate": {
                "csr": CSR_STR,
                "common_name": "example.com",
                "dns_names": names,
                "signature_hash": "sha256",
            },
            "organization": {"id": 111111},
            "custom_expiration_date": arrow.get(2017, 5, 7).format("YYYY-MM-DD"),
        }

        assert expected == plugin.map_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_cis_fields_with_validity_years(mock_current_app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2018, 11, 3))

    with patch('lemur.plugins.lemur_digicert.plugin.signature_hash') as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = [u"one.example.com", u"two.example.com", u"three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
            "organization": "Example, Inc.",
            "organizational_unit": "Example Org",
            "validity_years": 2,
            "authority": authority,
        }

        expected = {
            "common_name": "example.com",
            "csr": CSR_STR,
            "additional_dns_names": names,
            "signature_hash": "sha256",
            "organization": {"name": "Example, Inc."},
            "validity": {
                "valid_to": arrow.get(2018, 11, 3).format("YYYY-MM-DDTHH:mm:ss") + "Z"
            },
            "profile_name": None,
        }

        assert expected == plugin.map_cis_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_cis_fields_with_validity_end_and_start(mock_current_app, app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 5, 7))

    with patch('lemur.plugins.lemur_digicert.plugin.signature_hash') as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = [u"one.example.com", u"two.example.com", u"three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
            "organization": "Example, Inc.",
            "organizational_unit": "Example Org",
            "validity_end": arrow.get(2017, 5, 7),
            "validity_start": arrow.get(2016, 10, 30),
            "authority": authority
        }

        expected = {
            "common_name": "example.com",
            "csr": CSR_STR,
            "additional_dns_names": names,
            "signature_hash": "sha256",
            "organization": {"name": "Example, Inc."},
            "validity": {
                "valid_to": arrow.get(2017, 5, 7).format("YYYY-MM-DDTHH:mm:ss") + "Z"
            },
            "profile_name": None,
        }

        assert expected == plugin.map_cis_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_signature_hash(mock_current_app, app):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    assert plugin.signature_hash(None) == "sha256"
    assert plugin.signature_hash("sha256WithRSA") == "sha256"
    assert plugin.signature_hash("sha384WithRSA") == "sha384"
    assert plugin.signature_hash("sha512WithRSA") == "sha512"

    with pytest.raises(Exception):
        plugin.signature_hash("sdfdsf")


def test_issuer_plugin_create_certificate(
        certificate_="""\
-----BEGIN CERTIFICATE-----
abc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
def
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ghi
-----END CERTIFICATE-----
"""
):
    import requests_mock
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    pem_fixture = certificate_

    subject = DigiCertIssuerPlugin()
    adapter = requests_mock.Adapter()
    adapter.register_uri(
        "POST",
        "mock://www.digicert.com/services/v2/order/certificate/ssl_plus",
        text=json.dumps({"id": "id123"}),
    )
    adapter.register_uri(
        "GET",
        "mock://www.digicert.com/services/v2/order/certificate/id123",
        text=json.dumps({"status": "issued", "certificate": {"id": "cert123"}}),
    )
    adapter.register_uri(
        "GET",
        "mock://www.digicert.com/services/v2/certificate/cert123/download/format/pem_all",
        text=pem_fixture,
    )
    subject.session.mount("mock", adapter)

    cert, intermediate, external_id = subject.create_certificate(
        "", {"common_name": "test.com"}
    )

    assert cert == "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"
    assert intermediate == "-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----"


@patch("lemur.pending_certificates.models.PendingCertificate")
def test_cancel_ordered_certificate(mock_pending_cert):
    import requests_mock
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    mock_pending_cert.external_id = 1234
    subject = DigiCertIssuerPlugin()
    adapter = requests_mock.Adapter()
    adapter.register_uri(
        "PUT",
        "mock://www.digicert.com/services/v2/order/certificate/1234/status",
        status_code=204,
    )
    adapter.register_uri(
        "PUT",
        "mock://www.digicert.com/services/v2/order/certificate/111/status",
        status_code=404,
    )
    subject.session.mount("mock", adapter)
    data = {"note": "Test"}
    subject.cancel_ordered_certificate(mock_pending_cert, **data)

    # A non-existing order id, does not raise exception because if it doesn't exist, then it doesn't matter
    mock_pending_cert.external_id = 111
    subject.cancel_ordered_certificate(mock_pending_cert, **data)
