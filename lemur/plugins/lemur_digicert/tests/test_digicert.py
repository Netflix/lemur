import pytest
import arrow
import json
from freezegun import freeze_time

from lemur.tests.vectors import CSR_STR

from cryptography import x509


def test_map_fields_with_validity_end_and_start(app):
    from lemur.plugins.lemur_digicert.plugin import map_fields

    names = [u'one.example.com', u'two.example.com', u'three.example.com']

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [x509.DNSName(x) for x in names]
            }
        },
        'validity_end': arrow.get(2017, 5, 7),
        'validity_start': arrow.get(2016, 10, 30)
    }

    data = map_fields(options, CSR_STR)

    assert data == {
        'certificate': {
            'csr': CSR_STR,
            'common_name': 'example.com',
            'dns_names': names,
            'signature_hash': 'sha256'
        },
        'organization': {'id': 111111},
        'custom_expiration_date': arrow.get(2017, 5, 7).format('YYYY-MM-DD')
    }


def test_map_fields_with_validity_years(app):
    from lemur.plugins.lemur_digicert.plugin import map_fields

    names = [u'one.example.com', u'two.example.com', u'three.example.com']

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [x509.DNSName(x) for x in names]
            }
        },
        'validity_years': 2,
        'validity_end': arrow.get(2017, 10, 30)
    }

    data = map_fields(options, CSR_STR)

    assert data == {
        'certificate': {
            'csr': CSR_STR,
            'common_name': 'example.com',
            'dns_names': names,
            'signature_hash': 'sha256'
        },
        'organization': {'id': 111111},
        'validity_years': 2
    }


def test_map_cis_fields(app):
    from lemur.plugins.lemur_digicert.plugin import map_cis_fields

    names = [u'one.example.com', u'two.example.com', u'three.example.com']

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [x509.DNSName(x) for x in names]
            }
        },
        'organization': 'Example, Inc.',
        'organizational_unit': 'Example Org',
        'validity_end': arrow.get(2017, 5, 7),
        'validity_start': arrow.get(2016, 10, 30)
    }

    data = map_cis_fields(options, CSR_STR)

    assert data == {
        'common_name': 'example.com',
        'csr': CSR_STR,
        'additional_dns_names': names,
        'signature_hash': 'sha256',
        'organization': {'name': 'Example, Inc.', 'units': ['Example Org']},
        'validity': {
            'valid_to': arrow.get(2017, 5, 7).format('YYYY-MM-DD')
        },
        'profile_name': None
    }

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [x509.DNSName(x) for x in names]
            }
        },
        'organization': 'Example, Inc.',
        'organizational_unit': 'Example Org',
        'validity_years': 2
    }

    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        data = map_cis_fields(options, CSR_STR)

        assert data == {
            'common_name': 'example.com',
            'csr': CSR_STR,
            'additional_dns_names': names,
            'signature_hash': 'sha256',
            'organization': {'name': 'Example, Inc.', 'units': ['Example Org']},
            'validity': {
                'valid_to': arrow.get(2018, 11, 3).format('YYYY-MM-DD')
            },
            'profile_name': None
        }


def test_signature_hash(app):
    from lemur.plugins.lemur_digicert.plugin import signature_hash

    assert signature_hash(None) == 'sha256'
    assert signature_hash('sha256WithRSA') == 'sha256'
    assert signature_hash('sha384WithRSA') == 'sha384'
    assert signature_hash('sha512WithRSA') == 'sha512'

    with pytest.raises(Exception):
        signature_hash('sdfdsf')


def test_issuer_plugin_create_certificate():
    import requests_mock
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    pem_fixture = """\
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

    subject = DigiCertIssuerPlugin()
    adapter = requests_mock.Adapter()
    adapter.register_uri('POST', 'mock://www.digicert.com/services/v2/order/certificate/ssl_plus', text=json.dumps({'id': 'id123'}))
    adapter.register_uri('GET', 'mock://www.digicert.com/services/v2/order/certificate/id123', text=json.dumps({'status': 'issued', 'certificate': {'id': 'cert123'}}))
    adapter.register_uri('GET', 'mock://www.digicert.com/services/v2/certificate/cert123/download/format/pem_all', text=pem_fixture)
    subject.session.mount('mock', adapter)

    cert, intermediate, external_id = subject.create_certificate("", {'common_name': 'test.com'})

    assert cert == "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"
    assert intermediate == "-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----"
