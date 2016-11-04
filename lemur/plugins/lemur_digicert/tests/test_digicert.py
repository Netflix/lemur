import pytest
import arrow
from freezegun import freeze_time

from lemur.tests.vectors import CSR_STR


def test_create_certificate(app):
    from lemur.plugins.base import plugins
    p = plugins.get('digicert-issuer')

    names = ['one.example.com', 'two.example.com', 'three.example.com']

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [{'name_type': 'DNSName', 'value': x} for x in names]
            }
        },
        'validity_end': arrow.get(2017, 5, 7),
        'validity_start': arrow.get(2016, 10, 30)
    }

    server_cert, int_cert = p.create_certificate(CSR_STR, options)
    assert server_cert == ''
    assert int_cert == ''


def test_process_options(app):
    from lemur.plugins.lemur_digicert.plugin import process_options

    names = ['one.example.com', 'two.example.com', 'three.example.com']

    options = {
        'common_name': 'example.com',
        'owner': 'bob@example.com',
        'description': 'test certificate',
        'extensions': {
            'sub_alt_names': {
                'names': [{'name_type': 'DNSName', 'value': x} for x in names]
            }
        },
        'validity_end': arrow.get(2017, 5, 7),
        'validity_start': arrow.get(2016, 10, 30)
    }

    data = process_options(options, CSR_STR)

    assert data == {
        'certificate': {
            'csr': CSR_STR,
            'common_name': 'example.com',
            'dns_names': names,
            'signature_hash': 'sha256'
        },
        'organization': {'id': 'org-id'},
        'validity_years': '1',
        'custom_expiration_date': arrow.get(2017, 5, 7).format('YYYY-MM-DD')
    }


def test_issuance():
    from lemur.plugins.lemur_digicert.plugin import get_issuance

    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        options = {
            'validity_end': arrow.get(2018, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        end_date, period = get_issuance(options)

        assert period == '2'

        options = {
            'validity_end': arrow.get(2017, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        end_date, period = get_issuance(options)

        assert period == '1'

        options = {
            'validity_end': arrow.get(2020, 5, 7),
            'validity_start': arrow.get(2016, 10, 30)
        }

        with pytest.raises(Exception):
            end_date, period = get_issuance(options)


def test_signature_hash(app):
    from lemur.plugins.lemur_digicert.plugin import signature_hash

    assert signature_hash(None) == 'sha256'
    assert signature_hash('sha256WithRSA') == 'sha256'
    assert signature_hash('sha384WithRSA') == 'sha384'
    assert signature_hash('sha512WithRSA') == 'sha512'

    with pytest.raises(Exception):
        signature_hash('sdfdsf')
