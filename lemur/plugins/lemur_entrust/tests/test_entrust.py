from unittest.mock import patch, Mock

import arrow
from cryptography import x509
from lemur.plugins.lemur_entrust import plugin
from freezegun import freeze_time


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
def test_determine_end_date(mock_current_app):
    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        assert arrow.get(2017, 12, 3).format('YYYY-MM-DD') == plugin.determine_end_date(0)  # 1 year + 1 month
        assert arrow.get(2017, 3, 5).format('YYYY-MM-DD') == plugin.determine_end_date(arrow.get(2017, 3, 5))
        assert arrow.get(2017, 12, 3).format('YYYY-MM-DD') == plugin.determine_end_date(arrow.get(2020, 5, 7))


@patch("lemur.plugins.lemur_entrust.plugin.current_app")
def test_process_options(mock_current_app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 11, 5).format('YYYY-MM-DD'))
    authority.name = "Entrust"
    names = [u"one.example.com", u"two.example.com", u"three.example.com"]
    options = {
        "common_name": "example.com",
        "owner": "bob@example.com",
        "description": "test certificate",
        "extensions": {"sub_alt_names": {"names": [x509.DNSName(x) for x in names]}},
        "organization": "Example, Inc.",
        "organizational_unit": "Example Org",
        "validity_end": arrow.utcnow().shift(years=1, months=+1),
        "authority": authority,
    }

    expected = {
        "signingAlg": "SHA-2",
        "eku": "SERVER_AND_CLIENT_AUTH",
        "certType": "ADVANTAGE_SSL",
        "certExpiryDate": arrow.get(2017, 11, 5).format('YYYY-MM-DD'),
        "tracking": {
            "requesterName": mock_current_app.config.get("ENTRUST_NAME"),
            "requesterEmail": mock_current_app.config.get("ENTRUST_EMAIL"),
            "requesterPhone": mock_current_app.config.get("ENTRUST_PHONE")
        },
        "org": "Example, Inc.",
        "clientId": 1
    }

    client_id = 1
    assert expected == plugin.process_options(options, client_id)


def test_create_authority(app):
    from lemur.plugins.base import plugins

    options = {
        "name": "test Entrust authority"
    }
    p = plugins.get("entrust-issuer")
    entrust_root, intermediate, role = p.create_authority(options)
    assert role == [{"username": "", "password": "", "name": "entrust_test_Entrust_authority_admin"}]


def test_deactivate_certificate(app):
    from lemur.plugins.base import plugins
    import requests_mock
    p = plugins.get("entrust-issuer")

    mock_cert = Mock()
    mock_cert.external_id = 1

    p.options = [
            {
                "name": "staging_account",
                "type": "bool",
                "required": True,
                "helpMessage": "Set to True if this is an Entrust staging account.",
                "default": False,
                "value": True,
            }
    ]
    try:
        p.deactivate_certificate(mock_cert)
        assert False
    except Exception as inst:
        assert inst.args[0] == "This issuer is not configured to deactivate certificates."
