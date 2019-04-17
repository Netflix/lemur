from __future__ import unicode_literals  # at top of module

import datetime
import json

import arrow
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from marshmallow import ValidationError
from freezegun import freeze_time
from mock import patch

from lemur.certificates.service import create_csr
from lemur.certificates.views import *  # noqa
from lemur.common import utils
from lemur.domains.models import Domain


from lemur.tests.vectors import VALID_ADMIN_API_TOKEN, VALID_ADMIN_HEADER_TOKEN, VALID_USER_HEADER_TOKEN, CSR_STR, \
    INTERMEDIATE_CERT_STR, SAN_CERT_STR, SAN_CERT_CSR, SAN_CERT_KEY, ROOTCA_KEY, ROOTCA_CERT_STR


def test_get_or_increase_name(session, certificate):
    from lemur.certificates.models import get_or_increase_name
    from lemur.tests.factories import CertificateFactory

    serial = 'AFF2DB4F8D2D4D8E80FA382AE27C2333'

    assert get_or_increase_name(certificate.name, certificate.serial) == '{0}-{1}'.format(certificate.name, serial)

    certificate.name = 'test-cert-11111111'
    assert get_or_increase_name(certificate.name, certificate.serial) == 'test-cert-11111111-' + serial

    certificate.name = 'test-cert-11111111-1'
    assert get_or_increase_name('test-cert-11111111-1', certificate.serial) == 'test-cert-11111111-1-' + serial

    cert2 = CertificateFactory(name='certificate1-' + serial)
    session.commit()

    assert get_or_increase_name('certificate1', int(serial, 16)) == 'certificate1-{}-1'.format(serial)


def test_get_all_certs(session, certificate):
    from lemur.certificates.service import get_all_certs
    assert len(get_all_certs()) > 1


def test_get_by_name(session, certificate):
    from lemur.certificates.service import get_by_name

    found = get_by_name(certificate.name)

    assert found


def test_get_by_serial(session, certificate):
    from lemur.certificates.service import get_by_serial

    found = get_by_serial(certificate.serial)

    assert found


def test_delete_cert(session):
    from lemur.certificates.service import delete, get
    from lemur.tests.factories import CertificateFactory

    delete_this = CertificateFactory(name='DELETEME')
    session.commit()

    cert_exists = get(delete_this.id)

    # it needs to exist first
    assert cert_exists

    delete(delete_this.id)
    cert_exists = get(delete_this.id)

    # then not exist after delete
    assert not cert_exists


def test_get_by_attributes(session, certificate):
    from lemur.certificates.service import get_by_attributes

    # Should get one cert
    certificate1 = get_by_attributes({
        'name': 'SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231'
    })

    # Should get one cert using multiple attrs
    certificate2 = get_by_attributes({
        'name': 'test-cert-11111111-1',
        'cn': 'san.example.org'
    })

    # Should get multiple certs
    multiple = get_by_attributes({
        'cn': 'LemurTrust Unittests Class 1 CA 2018',
        'issuer': 'LemurTrustUnittestsRootCA2018'
    })

    assert len(certificate1) == 1
    assert len(certificate2) == 1
    assert len(multiple) > 1


def test_find_duplicates(session):
    from lemur.certificates.service import find_duplicates

    cert = {
        'body': SAN_CERT_STR,
        'chain': INTERMEDIATE_CERT_STR
    }

    dups1 = find_duplicates(cert)

    cert['chain'] = ''

    dups2 = find_duplicates(cert)

    assert len(dups1) > 0
    assert len(dups2) > 0


def test_get_certificate_primitives(certificate):
    from lemur.certificates.service import get_certificate_primitives

    names = [x509.DNSName(x.name) for x in certificate.domains]

    with freeze_time(datetime.date(year=2016, month=10, day=30)):
        primitives = get_certificate_primitives(certificate)
        assert len(primitives) == 26


def test_certificate_output_schema(session, certificate, issuer_plugin):
    from lemur.certificates.schemas import CertificateOutputSchema

    # Clear the cached attribute first
    if 'parsed_cert' in certificate.__dict__:
        del certificate.__dict__['parsed_cert']

    # Make sure serialization parses the cert only once (uses cached 'parsed_cert' attribute)
    with patch('lemur.common.utils.parse_certificate', side_effect=utils.parse_certificate) as wrapper:
        data, errors = CertificateOutputSchema().dump(certificate)
        assert data['issuer'] == 'LemurTrustUnittestsClass1CA2018'

    assert wrapper.call_count == 1


def test_certificate_edit_schema(session):
    from lemur.certificates.schemas import CertificateEditInputSchema

    input_data = {'owner': 'bob@example.com'}
    data, errors = CertificateEditInputSchema().load(input_data)
    assert len(data['notifications']) == 3


def test_authority_key_identifier_schema():
    from lemur.schemas import AuthorityKeyIdentifierSchema
    input_data = {
        'useKeyIdentifier': True,
        'useAuthorityCert': True
    }

    data, errors = AuthorityKeyIdentifierSchema().load(input_data)

    assert sorted(data) == sorted({
        'use_key_identifier': True,
        'use_authority_cert': True
    })
    assert not errors

    data, errors = AuthorityKeyIdentifierSchema().dumps(data)
    assert sorted(data) == sorted(json.dumps(input_data))
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
        }
    }

    data, errors = ExtensionSchema().load(input_data)
    assert not errors

    data, errors = ExtensionSchema().dump(data)
    assert not errors


def test_certificate_input_schema(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': arrow.get(2018, 11, 9).isoformat(),
        'validityEnd': arrow.get(2019, 11, 9).isoformat(),
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    assert data['authority'].id == authority.id

    # make sure the defaults got set
    assert data['common_name'] == 'test.example.com'
    assert data['country'] == 'US'
    assert data['location'] == 'Los Gatos'

    assert len(data.keys()) == 19


def test_certificate_input_with_extensions(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        'commonName': 'test.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'extensions': {
            'keyUsage': {
                'digital_signature': True
            },
            'extendedKeyUsage': {
                'useClientAuthentication': True,
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
        },
        'dnsProvider': None,
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
        'validityYears': 100,
        'dnsProvider': None,
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
        'validityYears': 1,
        'dnsProvider': None,
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
        'validityEnd': '2020-01-01T00:00:01',
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_cn_admin(client, authority, logged_in_admin):
    """Admin is exempt from CN/SAN domain restrictions."""
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': '*.admin-overrides-whitelist.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01',
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_allowed_names(client, authority, session, logged_in_user):
    """Test for allowed CN and SAN values."""
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': 'Names with spaces are not checked',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01',
        'extensions': {
            'subAltNames': {
                'names': [
                    {'nameType': 'DNSName', 'value': 'allowed.example.com'},
                    {'nameType': 'IPAddress', 'value': '127.0.0.1'},
                ]
            }
        },
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_incative_authority(client, authority, session, logged_in_user):
    """Cannot issue certificates with an inactive authority."""
    from lemur.certificates.schemas import CertificateInputSchema

    authority.active = False
    session.add(authority)

    input_data = {
        'commonName': 'foo.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01',
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors['authority'][0] == "The authority is inactive."


def test_certificate_disallowed_names(client, authority, session, logged_in_user):
    """The CN and SAN are disallowed by LEMUR_WHITELISTED_DOMAINS."""
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': '*.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01',
        'extensions': {
            'subAltNames': {
                'names': [
                    {'nameType': 'DNSName', 'value': 'allowed.example.com'},
                    {'nameType': 'DNSName', 'value': 'evilhacker.org'},
                ]
            }
        },
        'dnsProvider': None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors['common_name'][0].startswith("Domain *.example.com does not match whitelisted domain patterns")
    assert (errors['extensions']['sub_alt_names']['names'][0]
            .startswith("Domain evilhacker.org does not match whitelisted domain patterns"))


def test_certificate_sensitive_name(client, authority, session, logged_in_user):
    """The CN is disallowed by 'sensitive' flag on Domain model."""
    from lemur.certificates.schemas import CertificateInputSchema
    input_data = {
        'commonName': 'sensitive.example.com',
        'owner': 'jim@example.com',
        'authority': {'id': authority.id},
        'description': 'testtestest',
        'validityStart': '2020-01-01T00:00:00',
        'validityEnd': '2020-01-01T00:00:01',
        'dnsProvider': None,
    }
    session.add(Domain(name='sensitive.example.com', sensitive=True))

    data, errors = CertificateInputSchema().load(input_data)
    assert errors['common_name'][0].startswith("Domain sensitive.example.com has been marked as sensitive")


def test_certificate_upload_schema_ok(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'name': 'Jane',
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
        'privateKey': SAN_CERT_KEY,
        'chain': INTERMEDIATE_CERT_STR,
        'csr': SAN_CERT_CSR,
        'external_id': '1234',
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_minimal(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_long_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
        'chain': INTERMEDIATE_CERT_STR + '\n' + ROOTCA_CERT_STR
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_invalid_body(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': 'Hereby I certify that this is a valid body',
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'body': ['Public certificate presented is not valid.']}


def test_certificate_upload_schema_invalid_pkey(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
        'privateKey': 'Look at me Im a private key!!111',
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'private_key': ['Private key presented is not valid.']}


def test_certificate_upload_schema_invalid_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'body': SAN_CERT_STR,
        'chain': 'CHAINSAW',
        'owner': 'pwner@example.com',
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'chain': ['Invalid certificate in certificate chain.']}


def test_certificate_upload_schema_wrong_pkey(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'body': SAN_CERT_STR,
        'privateKey': ROOTCA_KEY,
        'chain': INTERMEDIATE_CERT_STR,
        'owner': 'pwner@example.com',
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'_schema': ['Private key does not match certificate.']}


def test_certificate_upload_schema_wrong_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
        'chain': ROOTCA_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'_schema': ["Incorrect chain certificate(s) provided: 'san.example.org' is not signed by "
                                  "'LemurTrust Unittests Root CA 2018'"]}


def test_certificate_upload_schema_wrong_chain_2nd(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema
    data = {
        'owner': 'pwner@example.com',
        'body': SAN_CERT_STR,
        'chain': INTERMEDIATE_CERT_STR + '\n' + SAN_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {'_schema': ["Incorrect chain certificate(s) provided: 'LemurTrust Unittests Class 1 CA 2018' is "
                                  "not signed by 'san.example.org'"]}


def test_create_basic_csr(client):
    csr_config = dict(
        common_name='example.com',
        organization='Example, Inc.',
        organizational_unit='Operations',
        country='US',
        state='CA',
        location='A place',
        owner='joe@example.com',
        key_type='RSA2048',
        extensions=dict(names=dict(sub_alt_names=x509.SubjectAlternativeName([x509.DNSName('test.example.com'), x509.DNSName('test2.example.com')])))
    )
    csr, pem = create_csr(**csr_config)

    csr = x509.load_pem_x509_csr(csr.encode('utf-8'), default_backend())
    for name in csr.subject:
        assert name.value in csr_config.values()


def test_csr_empty_san(client):
    """Test that an empty "names" list does not produce a CSR with empty SubjectAltNames extension.

    The Lemur UI always submits this extension even when no alt names are defined.
    """

    csr_text, pkey = create_csr(
        common_name='daniel-san.example.com',
        owner='daniel-san@example.com',
        key_type='RSA2048',
        extensions={'sub_alt_names': {'names': x509.SubjectAlternativeName([])}}
    )

    csr = x509.load_pem_x509_csr(csr_text.encode('utf-8'), default_backend())

    with pytest.raises(x509.ExtensionNotFound):
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_csr_disallowed_cn(client, logged_in_user):
    """Domain name CN is disallowed via LEMUR_WHITELISTED_DOMAINS."""
    from lemur.common import validators

    request, pkey = create_csr(
        common_name='evilhacker.org',
        owner='joe@example.com',
        key_type='RSA2048',
    )
    with pytest.raises(ValidationError) as err:
        validators.csr(request)
    assert str(err.value).startswith('Domain evilhacker.org does not match whitelisted domain patterns')


def test_csr_disallowed_san(client, logged_in_user):
    """SAN name is disallowed by LEMUR_WHITELISTED_DOMAINS."""
    from lemur.common import validators

    request, pkey = create_csr(
        common_name="CN with spaces isn't a domain and is thus allowed",
        owner='joe@example.com',
        key_type='RSA2048',
        extensions={'sub_alt_names': {'names': x509.SubjectAlternativeName([x509.DNSName('evilhacker.org')])}}
    )
    with pytest.raises(ValidationError) as err:
        validators.csr(request)
    assert str(err.value).startswith('Domain evilhacker.org does not match whitelisted domain patterns')


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
    cert_body, private_key, chain, external_id, csr = mint(authority=authority, csr=CSR_STR)
    assert cert_body == SAN_CERT_STR


def test_create_certificate(issuer_plugin, authority, user):
    from lemur.certificates.service import create
    cert = create(authority=authority, csr=CSR_STR, owner='joe@example.com', creator=user['user'])
    assert str(cert.not_after) == '2047-12-31T22:00:00+00:00'
    assert str(cert.not_before) == '2017-12-31T22:00:00+00:00'
    assert cert.issuer == 'LemurTrustUnittestsClass1CA2018'
    assert cert.name == 'SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231-AFF2DB4F8D2D4D8E80FA382AE27C2333'

    cert = create(authority=authority, csr=CSR_STR, owner='joe@example.com', name='ACustomName1', creator=user['user'])
    assert cert.name == 'ACustomName1'


def test_reissue_certificate(issuer_plugin, crypto_authority, certificate, logged_in_user):
    from lemur.certificates.service import reissue_certificate

    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority
    new_cert = reissue_certificate(certificate)
    assert new_cert


def test_create_csr():
    csr, private_key = create_csr(owner='joe@example.com', common_name='ACommonName', organization='test', organizational_unit='Meters', country='US',
                                  state='CA', location='Here', key_type='RSA2048')
    assert csr
    assert private_key

    extensions = {'sub_alt_names': {'names': x509.SubjectAlternativeName([x509.DNSName('AnotherCommonName')])}}
    csr, private_key = create_csr(owner='joe@example.com', common_name='ACommonName', organization='test', organizational_unit='Meters', country='US',
                                  state='CA', location='Here', extensions=extensions, key_type='RSA2048')
    assert csr
    assert private_key


def test_import(user):
    from lemur.certificates.service import import_certificate
    cert = import_certificate(body=SAN_CERT_STR, chain=INTERMEDIATE_CERT_STR, private_key=SAN_CERT_KEY, creator=user['user'])
    assert str(cert.not_after) == '2047-12-31T22:00:00+00:00'
    assert str(cert.not_before) == '2017-12-31T22:00:00+00:00'
    assert cert.issuer == 'LemurTrustUnittestsClass1CA2018'
    assert cert.name.startswith('SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231')

    cert = import_certificate(body=SAN_CERT_STR, chain=INTERMEDIATE_CERT_STR, private_key=SAN_CERT_KEY, owner='joe@example.com', name='ACustomName2', creator=user['user'])
    assert cert.name == 'ACustomName2'


@pytest.mark.skip
def test_upload(user):
    from lemur.certificates.service import upload
    cert = upload(body=SAN_CERT_STR, chain=INTERMEDIATE_CERT_STR, private_key=SAN_CERT_KEY, owner='joe@example.com', creator=user['user'])
    assert str(cert.not_after) == '2040-01-01T20:30:52+00:00'
    assert str(cert.not_before) == '2015-06-26T20:30:52+00:00'
    assert cert.issuer == 'Example'
    assert cert.name == 'long.lived.com-Example-20150626-20400101-3'

    cert = upload(body=SAN_CERT_STR, chain=INTERMEDIATE_CERT_STR, private_key=SAN_CERT_KEY, owner='joe@example.com', name='ACustomName', creator=user['user'])
    assert 'ACustomName' in cert.name


# verify upload with a private key as a str
def test_upload_private_key_str(user):
    from lemur.certificates.service import upload
    cert = upload(body=SAN_CERT_STR, chain=INTERMEDIATE_CERT_STR, private_key=SAN_CERT_KEY, owner='joe@example.com', name='ACustomName', creator=user['user'])
    assert cert


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    (VALID_ADMIN_API_TOKEN, 200),
    ('', 401)
])
def test_certificate_get_private_key(client, token, status):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    (VALID_ADMIN_API_TOKEN, 200),
    ('', 401)
])
def test_certificate_get(client, token, status):
    assert client.get(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


def test_certificate_get_body(client):
    response_body = client.get(api.url_for(Certificates, certificate_id=1), headers=VALID_USER_HEADER_TOKEN).json
    assert response_body['serial'] == '211983098819107449768450703123665283596'
    assert response_body['serialHex'] == '9F7A75B39DAE4C3F9524C68B06DA6A0C'
    assert response_body['distinguishedName'] == ('CN=LemurTrust Unittests Class 1 CA 2018,'
                                                  'O=LemurTrust Enterprises Ltd,'
                                                  'OU=Unittesting Operations Center,'
                                                  'C=EE,'
                                                  'ST=N/A,'
                                                  'L=Earth')


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_post(client, token, status):
    assert client.post(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    (VALID_ADMIN_API_TOKEN, 400),
    ('', 401)
])
def test_certificate_put(client, token, status):
    assert client.put(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


def test_certificate_put_with_data(client, certificate, issuer_plugin):
    resp = client.put(api.url_for(Certificates, certificate_id=certificate.id), data=json.dumps({'owner': 'bob@example.com', 'description': 'test', 'notify': True}), headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 204),
    (VALID_ADMIN_API_TOKEN, 412),
    ('', 401)
])
def test_certificate_delete(client, token, status):
    assert client.delete(api.url_for(Certificates, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 403),
    (VALID_ADMIN_HEADER_TOKEN, 204),
    (VALID_ADMIN_API_TOKEN, 204),
    ('', 401)
])
def test_invalid_certificate_delete(client, invalid_certificate, token, status):
    assert client.delete(
        api.url_for(Certificates, certificate_id=invalid_certificate.id), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_patch(client, token, status):
    assert client.patch(api.url_for(Certificates, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 200),
    (VALID_ADMIN_HEADER_TOKEN, 200),
    (VALID_ADMIN_API_TOKEN, 200),
    ('', 401)
])
def test_certificates_get(client, token, status):
    assert client.get(api.url_for(CertificatesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    (VALID_ADMIN_API_TOKEN, 400),
    ('', 401)
])
def test_certificates_post(client, token, status):
    assert client.post(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_put(client, token, status):
    assert client.put(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_delete(client, token, status):
    assert client.delete(api.url_for(CertificatesList), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_patch(client, token, status):
    assert client.patch(api.url_for(CertificatesList), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_post(client, token, status):
    assert client.post(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_put(client, token, status):
    assert client.put(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_delete(client, token, status):
    assert client.delete(api.url_for(CertificatePrivateKey, certificate_id=1), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificate_credentials_patch(client, token, status):
    assert client.patch(api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_get(client, token, status):
    assert client.get(api.url_for(CertificatesUpload), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 400),
    (VALID_ADMIN_HEADER_TOKEN, 400),
    (VALID_ADMIN_API_TOKEN, 400),
    ('', 401)
])
def test_certificates_upload_post(client, token, status):
    assert client.post(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_put(client, token, status):
    assert client.put(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_delete(client, token, status):
    assert client.delete(api.url_for(CertificatesUpload), headers=token).status_code == status


@pytest.mark.parametrize("token,status", [
    (VALID_USER_HEADER_TOKEN, 405),
    (VALID_ADMIN_HEADER_TOKEN, 405),
    (VALID_ADMIN_API_TOKEN, 405),
    ('', 405)
])
def test_certificates_upload_patch(client, token, status):
    assert client.patch(api.url_for(CertificatesUpload), data={}, headers=token).status_code == status


def test_sensitive_sort(client):
    resp = client.get(api.url_for(CertificatesList) + '?sortBy=private_key&sortDir=asc', headers=VALID_ADMIN_HEADER_TOKEN)
    assert "'private_key' is not sortable or filterable" in resp.json['message']


def test_boolean_filter(client):
    resp = client.get(api.url_for(CertificatesList) + '?filter=notify;true', headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
    # Also don't crash with invalid input (we currently treat that as false)
    resp = client.get(api.url_for(CertificatesList) + '?filter=notify;whatisthis', headers=VALID_ADMIN_HEADER_TOKEN)
    assert resp.status_code == 200
