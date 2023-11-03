from unittest.mock import patch, Mock

import arrow
from cryptography import x509
from cryptography.x509 import CertificateSigningRequest, Extension, Extensions
from lemur.plugins.lemur_entrust import plugin
from freezegun import freeze_time

_base_config = {
    "ENTRUST_API_CERT": "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----",
    "ENTRUST_API_KEY": False,
    "ENTRUST_API_USER": "test",
    "ENTRUST_API_PASS": "password",
    "ENTRUST_URL": "http",
    "ENTRUST_ROOT": None,
    "ENTRUST_NAME": "test",
    "ENTRUST_EMAIL": "test@lemur.net",
    "ENTRUST_PHONE": "0123456",
    "ENTRUST_PRODUCT_ENTRUST": "ADVANTAGE_SSL",
    'ENTRUST_USE_EKU': True,
}


def config_mock(*args):
    return _base_config.get(args[0])


def config_mock_infer_eku(*args):
    values = {**_base_config, 'ENTRUST_INFER_EKU': True}
    return values.get(args[0])


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
    names = ["one.example.com", "two.example.com", "three.example.com"]
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



@patch("lemur.plugins.lemur_entrust.plugin.current_app")
@patch("cryptography.x509.load_pem_x509_csr")
def test_process_options_infer_eku(mock_load_pem, mock_current_app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock_infer_eku)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 11, 5).format('YYYY-MM-DD'))
    authority.name = "Entrust"
    names = ["one.example.com", "two.example.com", "three.example.com"]
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

    client_id = 1
    csr = "csr"  # The actual value doesn't matter

    client_auth_oid = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
    server_auth_oid = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH
    client_eku_ext = x509.ExtendedKeyUsage([client_auth_oid])
    server_eku_ext = x509.ExtendedKeyUsage([server_auth_oid])
    both_eku_ext = x509.ExtendedKeyUsage([client_auth_oid, server_auth_oid])

    mock_csr = Mock(spec=CertificateSigningRequest)
    mock_csr.extensions = Extensions([Extension(oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE, critical=False, value=both_eku_ext)])
    mock_load_pem.return_value = mock_csr
    assert plugin.process_options(options, client_id, csr)['eku'] == 'SERVER_AND_CLIENT_AUTH'

    mock_csr.extensions = Extensions([Extension(oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE, critical=False, value=client_eku_ext)])
    assert plugin.process_options(options, client_id, csr)['eku'] == 'CLIENT_AUTH'

    mock_csr.extensions = Extensions([Extension(oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE, critical=False, value=server_eku_ext)])
    assert plugin.process_options(options, client_id, csr)['eku'] == 'SERVER_AUTH'


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
    p = plugins.get("entrust-issuer")

    mock_cert = Mock()
    mock_cert.external_id = 1

    p.options = [{
        "name": "staging_account",
        "type": "bool",
        "required": True,
        "helpMessage": "Set to True if this is an Entrust staging account.",
        "default": False,
        "value": True,
    }]
    try:
        p.deactivate_certificate(mock_cert)
        assert False
    except Exception as inst:
        assert inst.args[0] == "This issuer is not configured to deactivate certificates."
