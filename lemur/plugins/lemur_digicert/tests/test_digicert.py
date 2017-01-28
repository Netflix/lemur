import pytest
import arrow
from freezegun import freeze_time

from lemur.tests.vectors import CSR_STR

from cryptography import x509


def test_map_fields(app):
    from lemur.plugins.lemur_digicert.plugin import map_fields

    names = ['one.example.com', 'two.example.com', 'three.example.com']

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


def test_map_cis_fields(app):
    from lemur.plugins.lemur_digicert.plugin import map_cis_fields

    names = ['one.example.com', 'two.example.com', 'three.example.com']

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


def test_issuance():
    from lemur.plugins.lemur_digicert.plugin import get_issuance

    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        options = {
            'validity_end': arrow.get(2018, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        new_options = get_issuance(options)
        assert new_options['validity_years'] == 2

        options = {
            'validity_end': arrow.get(2017, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        new_options = get_issuance(options)
        assert new_options['validity_years'] == 1

        options = {
            'validity_end': arrow.get(2020, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        with pytest.raises(Exception):
            period = get_issuance(options)


def test_signature_hash(app):
    from lemur.plugins.lemur_digicert.plugin import signature_hash

    assert signature_hash(None) == 'sha256'
    assert signature_hash('sha256WithRSA') == 'sha256'
    assert signature_hash('sha384WithRSA') == 'sha384'
    assert signature_hash('sha512WithRSA') == 'sha512'

    with pytest.raises(Exception):
        signature_hash('sdfdsf')
