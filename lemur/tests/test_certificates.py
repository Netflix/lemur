from __future__ import unicode_literals    # at top of module

import pytest
import json
from lemur.certificates.views import *  # noqa

from .vectors import VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN


def test_authority_identifier_schema():
    from lemur.certificates.schemas import AuthorityIdentifierSchema
    input_data = {'useAuthorityCert': True}

    data, errors = AuthorityIdentifierSchema().load(input_data)

    assert data == {'use_authority_cert': True}
    assert not errors

    data, errors = AuthorityIdentifierSchema().dumps(data)
    assert not errors
    assert data == json.dumps(input_data)


def test_authority_key_identifier_schema():
    from lemur.certificates.schemas import AuthorityKeyIdentifierSchema
    input_data = {'useKeyIdentifier': True}

    data, errors = AuthorityKeyIdentifierSchema().load(input_data)

    assert data == {'use_key_identifier': True}
    assert not errors

    data, errors = AuthorityKeyIdentifierSchema().dumps(data)
    assert data == json.dumps(input_data)
    assert not errors


def test_certificate_info_access_schema():
    from lemur.certificates.schemas import CertificateInfoAccessSchema
    input_data = {'includeAIA': True}

    data, errors = CertificateInfoAccessSchema().load(input_data)
    assert not errors
    assert data == {'include_aia': True}

    data, errors = CertificateInfoAccessSchema().dump(data)
    assert not errors
    assert data == input_data


def test_subject_key_identifier_schema():
    from lemur.certificates.schemas import SubjectKeyIdentifierSchema

    input_data = {'includeSKI': True}

    data, errors = SubjectKeyIdentifierSchema().load(input_data)
    assert not errors
    assert data == {'include_ski': True}
    data, errors = SubjectKeyIdentifierSchema().dump(data)
    assert not errors
    assert data == input_data


def test_extension_schema():
    from lemur.certificates.schemas import ExtensionSchema

    input_data = {
        'keyUsage': {
            'useKeyEncipherment': True,
            'useDigitalSignature': True
        },
        'extendedKeyUsage': {
            'useServerAuthentication': True
        },
        'subjectKeyIdentifier': {
            'includeSKI': True
        },
        'subAltNames': {
            'names': [
                {'nameType': 'DNSName', 'value': 'test.example.com'}
            ]
        }
    }

    data, errors = ExtensionSchema().load(input_data)
    assert not errors


def test_certificate_input_schema(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    assert data['authority'].id == authority.id

    # make sure the defaults got set
    assert data['common_name'] == 'test.example.com'
    assert data['country'] == 'US'
    assert data['location'] == 'Los Gatos'

    assert len(data.keys()) == 12


def test_certificate_input_with_extensions(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'extensions': {
            'keyUsage': {
                'useKeyEncipherment': True,
                'useDigitalSignature': True
            },
            'extendedKeyUsage': {
                'useServerAuthentication': True
            },
            'subjectKeyIdentifier': {
                'includeSKI': True
            },
            'subAltNames': {
                'names': [
                    {'nameType': 'DNSName', 'value': 'test.example.com'}
                ]
            }
        }
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_out_of_range_date(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityYears': 100
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors

    input_data['validityStart'] = '2017-04-30T00:12:34.513631'

    data, errors = CertificateInputSchema().load(input_data)
    assert errors

    input_data['validityEnd'] = '2018-04-30T00:12:34.513631'

    data, errors = CertificateInputSchema().load(input_data)
    assert errors


def test_certificate_valid_years(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityYears': 3
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_valid_dates(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2017-04-30T00:12:34.513631',
        'validityEnd': '2018-04-30T00:12:34.513631'
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_sub_alt_name_schema():
    from lemur.certificates.schemas import SubAltNameSchema, SubAltNamesSchema
    input_data = {'nameType': 'DNSName', 'value': 'test.example.com'}

    data, errors = SubAltNameSchema().load(input_data)
    assert not errors
    assert data == {'name_type': 'DNSName', 'value': 'test.example.com'}

    data, errors = SubAltNameSchema().dumps(data)
    assert data == json.dumps(input_data)
    assert not errors

    input_datas = {'names': [input_data]}

    data, errors = SubAltNamesSchema().load(input_datas)
    assert not errors
    assert data == {'names': [{'name_type': 'DNSName', 'value': 'test.example.com'}]}

    data, errors = SubAltNamesSchema().dumps(data)
    assert data == json.dumps(input_datas)
    assert not errors


def test_key_usage_schema():
    from lemur.certificates.schemas import KeyUsageSchema

    input_data = {
        'useCRLSign': True,
        'useDataEncipherment': True,
        'useDecipherOnly': True,
        'useEncipherOnly': True,
        'useKeyEncipherment': True,
        'useDigitalSignature': True,
        'useNonRepudiation': True
    }

    data, errors = KeyUsageSchema().load(input_data)

    assert not errors
    assert data == {
        'use_crl_sign': True,
        'use_data_encipherment': True,
        'use_decipher_only': True,
        'use_encipher_only': True,
        'use_key_encipherment': True,
        'use_digital_signature': True,
        'use_non_repudiation': True
    }


def test_extended_key_usage_schema():
    from lemur.certificates.schemas import ExtendedKeyUsageSchema

    input_data = {
        'useServerAuthentication': True,
        'useClientAuthentication': True,
        'useEapOverLAN': True,
        'useEapOverPPP': True,
        'useOCSPSigning': True,
        'useSmartCardAuthentication': True,
        'useTimestamping': True
    }

    data, errors = ExtendedKeyUsageSchema().load(input_data)

    assert not errors
    assert data == {
        'use_server_authentication': True,
        'use_client_authentication': True,
        'use_eap_over_lan': True,
        'use_eap_over_ppp': True,
        'use_ocsp_signing': True,
        'use_smart_card_authentication': True,
        'use_timestamping': True
    }


def test_create_basic_csr(client):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from lemur.certificates.service import create_csr
    csr_config = dict(
        common_name='example.com',
        organization='Example, Inc.',
        organizational_unit='Operations',
        country='US',
        state='CA',
        location='A place',
        extensions=dict(names=dict(sub_alt_names=['test.example.com', 'test2.example.com']))
    )
    csr, pem = create_csr(csr_config)

    private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    csr = x509.load_pem_x509_csr(csr, default_backend())
    for name in csr.subject:
        assert name.value in csr_config.values()


def test_cert_get_cn(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import get_cn

    assert get_cn(INTERNAL_VALID_LONG_CERT) == 'long.lived.com'


def test_cert_get_sub_alt_domains(client):
    from .vectors import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import get_domains

    assert get_domains(INTERNAL_VALID_LONG_CERT) == []
    assert get_domains(INTERNAL_VALID_SAN_CERT) == ['example2.long.com', 'example3.long.com']


def test_cert_is_san(client):
    from .vectors import INTERNAL_VALID_SAN_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import is_san

    assert not is_san(INTERNAL_VALID_LONG_CERT)
    assert is_san(INTERNAL_VALID_SAN_CERT)


def test_cert_is_wildcard(client):
    from .vectors import INTERNAL_VALID_WILDCARD_CERT, INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import is_wildcard
    assert is_wildcard(INTERNAL_VALID_WILDCARD_CERT)
    assert not is_wildcard(INTERNAL_VALID_LONG_CERT)


def test_cert_get_bitstrength(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import get_bitstrength
    assert get_bitstrength(INTERNAL_VALID_LONG_CERT) == 2048


def test_cert_get_issuer(client):
    from .vectors import INTERNAL_VALID_LONG_CERT
    from lemur.certificates.models import get_issuer
    assert get_issuer(INTERNAL_VALID_LONG_CERT) == 'Example'


def test_get_name_from_arn(client):
    from lemur.certificates.models import get_name_from_arn
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_name_from_arn(arn) == 'mycertificate'


def test_get_account_number(client):
    from lemur.certificates.models import get_account_number
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_account_number(arn) == '11111111'


def test_create_name(client):
    from lemur.certificates.models import create_name
    from datetime import datetime
    assert create_name(
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        'example.com',
        False
    ) == 'example.com-ExampleInc-20150507-20150512'
    assert create_name(
        'Example Inc,',
        datetime(2015, 5, 7, 0, 0, 0),
        datetime(2015, 5, 12, 0, 0, 0),
        'example.com',
        True
    ) == 'SAN-example.com-ExampleInc-20150507-20150512'


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 404),
    (VALID_ADMIN_HEADER_TOKEN, 404),
    ('', 401)
])
def test_certificate_get(client, token, status):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_post(client, token, status):
    assert client.post(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_certificate_put(client, token, status):
    assert client.put(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_delete(client, token, status):
    assert client.delete(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_patch(client, token, status):
    assert client.patch(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_certificates_get(client, token, status):
    assert client.get(api.url_for(CertificatesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_certificates_post(client, token, status):
    assert client.post(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_put(client, token, status):
    assert client.put(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_delete(client, token, status):
    assert client.delete(api.url_for(CertificatesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_patch(client, token, status):
    assert client.patch(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 404),
    (VALID_ADMIN_HEADER_TOKEN, 404),
    ('', 401)
])
def test_certificate_credentials_get(client, token, status):
    assert client.get(api.url_for(CertificatePrivateKey, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_post(client, token, status):
    assert client.post(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_put(client, token, status):
    assert client.put(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_delete(client, token, status):
    assert client.delete(api.url_for(CertificatePrivateKey, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_patch(client, token, status):
    assert client.patch(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_get(client, token, status):
    assert client.get(api.url_for(CertificatesUpload), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    ('', 401)
])
def test_certificates_upload_post(client, token, status):
    assert client.post(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_put(client, token, status):
    assert client.put(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_delete(client, token, status):
    assert client.delete(api.url_for(CertificatesUpload), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_patch(client, token, status):
    assert client.patch(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status
