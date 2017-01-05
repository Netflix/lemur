from __future__ import unicode_literals    # at top of module

import json
import pytest
import datetime
import arrow

from freezegun import freeze_time

from lemur.certificates.views import *  # noqa

from lemur.tests.vectors import VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN, CSR_STR, \
    INTERNAL_VALID_LONG_STR, INTERNAL_VALID_SAN_STR, PRIVATE_KEY_STR


def test_get_certificate_primitives(certificate):
    from lemur.certificates.service import get_certificate_primitives

    names = [{'name_type': 'DNSName', 'value': x.name} for x in certificate.domains]

    data = {
        'common_name': certificate.cn,
        'owner': certificate.owner,
        'authority': certificate.authority,
        'description': certificate.description,
        'extensions': {
            'sub_alt_names': {
                'names': names
            }
        },
        'destinations': [],
        'roles': [],
        'validity_end': arrow.get(2021, 5, 7),
        'validity_start': arrow.get(2016, 10, 30),
        'country': 'US',
        'location': 'A place',
        'organization': 'Example',
        'organizational_unit': 'Operations',
        'state': 'CA'
    }

    with freeze_time(datetime.date(year=2016, month=10, day=30)):
        primitives = get_certificate_primitives(certificate)
        assert len(primitives) == 17


def test_certificate_edit_schema(session):
    from lemur.certificates.schemas import CertificateEditInputSchema

    input_data = {'owner': 'bob@example.com'}
    data, errors = CertificateEditInputSchema().load(input_data)
    assert len(data['notifications']) == 3


def test_authority_identifier_schema():
    from lemur.schemas import AuthorityIdentifierSchema
    input_data = {'useAuthorityCert': True}

    data, errors = AuthorityIdentifierSchema().load(input_data)

    assert data == {'use_authority_cert': True}
    assert not errors

    data, errors = AuthorityIdentifierSchema().dumps(data)
    assert not errors
    assert data == json.dumps(input_data)


def test_authority_key_identifier_schema():
    from lemur.schemas import AuthorityKeyIdentifierSchema
    input_data = {'useKeyIdentifier': True}

    data, errors = AuthorityKeyIdentifierSchema().load(input_data)

    assert data == {'use_key_identifier': True}
    assert not errors

    data, errors = AuthorityKeyIdentifierSchema().dumps(data)
    assert data == json.dumps(input_data)
    assert not errors


def test_certificate_info_access_schema():
    from lemur.schemas import CertificateInfoAccessSchema
    input_data = {'includeAIA': True}

    data, errors = CertificateInfoAccessSchema().load(input_data)
    assert not errors
    assert data == {'include_aia': True}

    data, errors = CertificateInfoAccessSchema().dump(data)
    assert not errors
    assert data == input_data


def test_subject_key_identifier_schema():
    from lemur.schemas import SubjectKeyIdentifierSchema

    input_data = {'includeSKI': True}

    data, errors = SubjectKeyIdentifierSchema().load(input_data)
    assert not errors
    assert data == {'include_ski': True}
    data, errors = SubjectKeyIdentifierSchema().dump(data)
    assert not errors
    assert data == input_data


def test_extension_schema(client):
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
        'validityEnd': arrow.get(2016, 11, 9).isoformat(),
        'validityStart': arrow.get(2015, 11, 9).isoformat()
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    assert data['authority'].id == authority.id

    # make sure the defaults got set
    assert data['common_name'] == 'test.example.com'
    assert data['country'] == 'US'
    assert data['location'] == 'Los Gatos'

    assert len(data.keys()) == 17


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
        'validityYears': 2
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
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01'
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_sub_alt_name_schema(session):
    from lemur.schemas import SubAltNameSchema  # SubAltNamesSchema
    input_data = {'nameType': 'DNSName', 'value': 'test.example.com'}

    data, errors = SubAltNameSchema().load(input_data)
    assert not errors
    assert data == {'name_type': 'DNSName', 'value': 'test.example.com'}

    data, errors = SubAltNameSchema().dumps(data)
    assert not errors

    input_datas = {'names': [input_data]}

    # data, errors = SubAltNamesSchema().load(input_datas)
    # assert not errors
    # assert data == {'names': [{'name_type': 'DNSName', 'value': 'test.example.com'}]}

    # data, errors = SubAltNamesSchema().dumps(data)
    # assert data == json.dumps(input_datas)
    # assert not errors

    input_data = {'nameType': 'CNAME', 'value': 'test.example.com'}
    data, errors = SubAltNameSchema().load(input_data)
    assert errors


def test_key_usage_schema():
    from lemur.schemas import KeyUsageSchema

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
    from lemur.schemas import ExtendedKeyUsageSchema

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
    from lemur.certificates.service import create_csr
    csr_config = dict(
        common_name='example.com',
        organization='Example, Inc.',
        organizational_unit='Operations',
        country='US',
        state='CA',
        location='A place',
        owner='joe@example.com',
        key_type='RSA2048',
        extensions=dict(names=dict(sub_alt_names=['test.example.com', 'test2.example.com']))
    )
    csr, pem = create_csr(**csr_config)

    csr = x509.load_pem_x509_csr(csr.encode('utf-8'), default_backend())
    for name in csr.subject:
        assert name.value in csr_config.values()


def test_get_name_from_arn(client):
    from lemur.certificates.service import get_name_from_arn
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_name_from_arn(arn) == 'mycertificate'


def test_get_account_number(client):
    from lemur.certificates.service import get_account_number
    arn = 'arn:aws:iam::11111111:server-certificate/mycertificate'
    assert get_account_number(arn) == '11111111'


def test_mint_certificate(issuer_plugin, authority):
    from lemur.certificates.service import mint
    cert_body, private_key, chain = mint(authority=authority, csr=CSR_STR)
    assert cert_body == INTERNAL_VALID_LONG_STR, INTERNAL_VALID_SAN_STR


def test_create_certificate(issuer_plugin, authority, user):
    from lemur.certificates.service import create
    cert = create(authority=authority, csr=CSR_STR, owner='joe@example.com', creator=user['user'])
    assert str(cert.not_after) == '2040-01-01T20:30:52+00:00'
    assert str(cert.not_before) == '2015-06-26T20:30:52+00:00'
    assert cert.issuer == 'Example'
    assert cert.name == 'long.lived.com-Example-20150626-20400101'

    cert = create(authority=authority, csr=CSR_STR, owner='joe@example.com', name='ACustomName1', creator=user['user'])
    assert cert.name == 'ACustomName1'


def test_reissue_certificate(issuer_plugin, authority, certificate):
    from lemur.certificates.service import reissue_certificate
    new_cert = reissue_certificate(certificate)
    assert new_cert


def test_create_csr():
    from lemur.certificates.service import create_csr

    csr, private_key = create_csr(owner='joe@example.com', common_name='ACommonName', organization='test', organizational_unit='Meters', country='US',
                                  state='CA', location='Here', key_type='RSA2048')
    assert csr
    assert private_key

    extensions = {'sub_alt_names': {'names': [{'name_type': 'DNSName', 'value': 'AnotherCommonName'}]}}
    csr, private_key = create_csr(owner='joe@example.com', common_name='ACommonName', organization='test', organizational_unit='Meters', country='US',
                                  state='CA', location='Here', extensions=extensions, key_type='RSA2048')
    assert csr
    assert private_key


def test_import(user):
    from lemur.certificates.service import import_certificate
    cert = import_certificate(body=INTERNAL_VALID_LONG_STR, chain=INTERNAL_VALID_SAN_STR, private_key=PRIVATE_KEY_STR, creator=user['user'])
    assert str(cert.not_after) == '2040-01-01T20:30:52+00:00'
    assert str(cert.not_before) == '2015-06-26T20:30:52+00:00'
    assert cert.issuer == 'Example'
    assert cert.name == 'long.lived.com-Example-20150626-20400101-2'

    cert = import_certificate(body=INTERNAL_VALID_LONG_STR, chain=INTERNAL_VALID_SAN_STR, private_key=PRIVATE_KEY_STR, owner='joe@example.com', name='ACustomName2', creator=user['user'])
    assert cert.name == 'ACustomName2'


def test_upload(user):
    from lemur.certificates.service import upload
    cert = upload(body=INTERNAL_VALID_LONG_STR, chain=INTERNAL_VALID_SAN_STR, private_key=PRIVATE_KEY_STR, owner='joe@example.com', creator=user['user'])
    assert str(cert.not_after) == '2040-01-01T20:30:52+00:00'
    assert str(cert.not_before) == '2015-06-26T20:30:52+00:00'
    assert cert.issuer == 'Example'
    assert cert.name == 'long.lived.com-Example-20150626-20400101-3'

    cert = upload(body=INTERNAL_VALID_LONG_STR, chain=INTERNAL_VALID_SAN_STR, private_key=PRIVATE_KEY_STR, owner='joe@example.com', name='ACustomName', creator=user['user'])
    assert 'ACustomName' in cert.name


# verify upload with a private key as a str
def test_upload_private_key_str(user):
    from lemur.certificates.service import upload
    cert = upload(body=INTERNAL_VALID_LONG_STR, chain=INTERNAL_VALID_SAN_STR, private_key=PRIVATE_KEY_STR, owner='joe@example.com', name='ACustomName', creator=user['user'])
    assert cert


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    ('', 401)
])
def test_certificate_get_private_key(client, token, status):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
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


def test_certificate_put_with_data(client, certificate, issuer_plugin):
    resp = client.put(api.url_for(Certificates, certificate_id=certificate.id), data=json.dumps({'owner': 'bob@example.com', 'description': 'test', 'notify': True}), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200


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
