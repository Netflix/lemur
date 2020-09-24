from unittest.mock import patch, Mock

import arrow
from cryptography import x509
from lemur.plugins.lemur_entrust import plugin


def config_mock(*args):
    values = {
        "ENTRUST_API_CERT": "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----",
        "ENTRUST_API_KEY": False,
        "ENTRUST_API_USER": "test",
        "ENTRUST_API_PASS": "password",
        "ENTRUST_URL": "http",
        "ENTRUST_ROOT": None,
        "ENTRUST_NAME": "test",
        "ENTRUST_EMAIL": "test@lemur.net",
        "ENTRUST_PHONE": "0123456",
        "ENTRUST_PRODUCT_ENTRUST": "ADVANTAGE_SSL"
    }
    return values[args[0]]


@patch("lemur.plugins.lemur_entrust.plugin.current_app")
def test_process_options(mock_current_app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2020, 10, 7).format('YYYY-MM-DD'))

    authority.name = "Entrust"
    names = [u"one.example.com", u"two.example.com", u"three.example.com"]
    options = {
        "common_name": "example.com",
        "owner": "bob@example.com",
        "description": "test certificate",
        "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
        "organization": "Example, Inc.",
        "organizational_unit": "Example Org",
        "validity_end": arrow.get(2020, 10, 7),
        "authority": authority,
    }

    expected = {
        "signingAlg": "SHA-2",
        "eku": "SERVER_AND_CLIENT_AUTH",
        "certType": "ADVANTAGE_SSL",
        "certExpiryDate": arrow.get(2020, 10, 7).format('YYYY-MM-DD'),
        "tracking": {
            "requesterName": mock_current_app.config.get("ENTRUST_NAME"),
            "requesterEmail": mock_current_app.config.get("ENTRUST_EMAIL"),
            "requesterPhone": mock_current_app.config.get("ENTRUST_PHONE")
        }
    }

    assert expected == plugin.process_options(options)
