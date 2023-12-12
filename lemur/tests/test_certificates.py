import datetime
import json
import ssl
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from tempfile import NamedTemporaryFile
from unittest.mock import patch

import arrow
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from freezegun import freeze_time
from marshmallow import ValidationError
from sqlalchemy.testing import fail

from lemur.certificates.service import create_csr, identify_and_persist_expiring_deployed_certificates, \
    reissue_certificate
from lemur.certificates.views import *  # noqa
from lemur.common import utils
from lemur.domains.models import Domain
from lemur.tests.factories import DestinationFactory, DuplicateAllowedDestinationFactory
from lemur.tests.test_messaging import create_cert_that_expires_in_days
from lemur.tests.vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
    CSR_STR,
    INTERMEDIATE_CERT_STR,
    SAN_CERT_STR,
    SAN_CERT_CSR,
    SAN_CERT_KEY,
    ROOTCA_KEY,
    ROOTCA_CERT_STR,
)


def test_get_or_increase_name(session, certificate):
    from lemur.certificates.models import get_or_increase_name
    from lemur.tests.factories import CertificateFactory

    serial = "AFF2DB4F8D2D4D8E80FA382AE27C2333"

    assert get_or_increase_name(
        certificate.name, certificate.serial
    ) == f"{certificate.name}-{serial}"

    certificate.name = "test-cert-11111111"
    assert (
        get_or_increase_name(certificate.name, certificate.serial)
        == "test-cert-11111111-" + serial
    )

    certificate.name = "test-cert-11111111-1"
    assert (
        get_or_increase_name("test-cert-11111111-1", certificate.serial)
        == "test-cert-11111111-1-" + serial
    )

    CertificateFactory(name="certificate1")
    CertificateFactory(name="certificate1-" + serial)
    session.commit()

    assert get_or_increase_name(
        "certificate1", int(serial, 16)
    ) == f"certificate1-{serial}-1"


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


def test_get_all_certs_attached_to_endpoint_without_autorotate(session):
    from lemur.certificates.service import get_all_certs_attached_to_endpoint_without_autorotate, \
        cleanup_after_revoke
    from lemur.tests.factories import EndpointFactory

    # add a certificate with endpoint
    EndpointFactory()

    list_before = get_all_certs_attached_to_endpoint_without_autorotate()
    len_list_before = len(list_before)
    assert len_list_before > 0
    # revoked the first certificate
    first_cert_with_endpoint = list_before[0]
    cleanup_after_revoke(first_cert_with_endpoint)

    list_after = get_all_certs_attached_to_endpoint_without_autorotate()
    assert len(list_after) + 1 == len_list_before


def test_delete_cert(session):
    from lemur.certificates.service import delete, get
    from lemur.tests.factories import CertificateFactory

    delete_this = CertificateFactory(name="DELETEME")
    session.commit()

    cert_exists = get(delete_this.id)

    # it needs to exist first
    assert cert_exists

    delete(delete_this.id)
    cert_exists = get(delete_this.id)

    # then not exist after delete
    assert not cert_exists


def test_cleanup_after_revoke(session, issuer_plugin, crypto_authority):
    from lemur.certificates.service import cleanup_after_revoke, get
    from lemur.tests.factories import CertificateFactory

    revoke_this = CertificateFactory(name="REVOKEME")
    session.commit()

    to_be_revoked = get(revoke_this.id)
    assert to_be_revoked
    to_be_revoked.notify = True
    to_be_revoked.rotation = True

    # Assuming the cert is revoked by corresponding issuer, update the records in lemur
    cleanup_after_revoke(to_be_revoked)
    revoked_cert = get(to_be_revoked.id)

    # then not exist after delete
    assert revoked_cert
    assert revoked_cert.status == "revoked"
    assert not revoked_cert.notify
    assert not revoked_cert.rotation
    assert not revoked_cert.destinations


def test_get_by_attributes(session, authority, user, certificate):
    from lemur.certificates.service import create, get_by_attributes

    create(
        authority=authority, csr=CSR_STR, owner="joe@example.com", creator=user["user"]
    )

    # Should get one cert
    certificate1 = get_by_attributes(
        {
            "name": "SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231"
        }
    )

    # Should get one cert using multiple attrs
    certificate2 = get_by_attributes(
        {"name": "test-cert-11111111-1", "cn": "san.example.org"}
    )

    # Should get multiple certs
    multiple = get_by_attributes(
        {
            "cn": "LemurTrust Unittests Class 1 CA 2018",
            "issuer": "LemurTrustUnittestsRootCA2018",
        }
    )

    assert len(certificate1) == 1
    assert len(certificate2) == 1
    assert len(multiple) > 1


def test_find_duplicates(session, issuer_plugin, user):
    from lemur.authorities.service import create
    from lemur.certificates.service import find_duplicates

    # create cert (duplicate of another one created in another test)
    cert = {"body": SAN_CERT_STR, "chain": INTERMEDIATE_CERT_STR}

    dups1 = find_duplicates(cert)

    # create authority with no chain
    authority = create(
        plugin={"plugin_object": issuer_plugin, "slug": issuer_plugin.slug},
        owner="jim@example.com",
        type="root",
        name="example authority 2",
        creator=user["user"],
    )

    cert["chain"] = ""

    dups2 = find_duplicates(cert)

    assert len(dups1) > 0
    assert len(dups2) > 0


def test_get_certificate_primitives(certificate, logged_in_user):
    from lemur.certificates.service import get_certificate_primitives

    names = [x509.DNSName(x.name) for x in certificate.domains]

    with freeze_time(datetime.date(year=2016, month=10, day=30)):
        primitives = get_certificate_primitives(certificate)
        assert len(primitives) == 26
        assert primitives["key_type"] == "RSA2048"


def test_certificate_output_schema(session, certificate, issuer_plugin):
    from lemur.certificates.schemas import CertificateOutputSchema

    # Clear the cached attribute first
    if "parsed_cert" in certificate.__dict__:
        del certificate.__dict__["parsed_cert"]

    # Make sure serialization parses the cert only once (uses cached 'parsed_cert' attribute)
    with patch(
        "lemur.common.utils.parse_certificate", side_effect=utils.parse_certificate
    ) as wrapper:
        data, errors = CertificateOutputSchema().dump(certificate)
        assert data["issuer"] == "LemurTrustUnittestsClass1CA2018"
        assert data["distinguishedName"] == "L=Earth,ST=N/A,C=EE,OU=Karate Lessons,O=Daniel San & co,CN=san.example.org"
        # Authority does not have 'cab_compliant', thus subject details should not be returned
        assert "organization" not in data

    assert wrapper.call_count == 1


def test_certificate_output_schema_subject_details(session, certificate, issuer_plugin):
    from lemur.certificates.schemas import CertificateOutputSchema
    from lemur.authorities.service import update_options

    # Mark authority as non-cab-compliant
    update_options(certificate.authority.id, '[{"name": "cab_compliant","value":false}]')

    data, errors = CertificateOutputSchema().dump(certificate)
    assert not errors
    assert data["issuer"] == "LemurTrustUnittestsClass1CA2018"
    assert data["distinguishedName"] == "L=Earth,ST=N/A,C=EE,OU=Karate Lessons,O=Daniel San & co,CN=san.example.org"

    # Original subject details should be returned because of cab_compliant option update above
    assert data["country"] == "EE"
    assert data["state"] == "N/A"
    assert data["location"] == "Earth"
    assert data["organization"] == "Daniel San & co"
    assert data["organizationalUnit"] == "Karate Lessons"

    # Mark authority as cab-compliant
    update_options(certificate.authority.id, '[{"name": "cab_compliant","value":true}]')
    data, errors = CertificateOutputSchema().dump(certificate)
    assert not errors
    assert "country" not in data
    assert "state" not in data
    assert "location" not in data
    assert "organization" not in data
    assert "organizationalUnit" not in data


def test_certificate_edit_schema(session):
    from lemur.certificates.schemas import CertificateEditInputSchema

    input_data = {"owner": "bob@example.com"}
    data, errors = CertificateEditInputSchema().load(input_data)

    assert not errors
    assert len(data["notifications"]) == 3
    assert data["roles"][0].name == input_data["owner"]


def test_authority_key_identifier_schema():
    from lemur.schemas import AuthorityKeyIdentifierSchema

    input_data = {"useKeyIdentifier": True, "useAuthorityCert": True}

    data, errors = AuthorityKeyIdentifierSchema().load(input_data)

    assert sorted(data) == sorted(
        {"use_key_identifier": True, "use_authority_cert": True}
    )
    assert not errors

    data, errors = AuthorityKeyIdentifierSchema().dumps(data)
    assert sorted(data) == sorted(json.dumps(input_data))
    assert not errors


def test_certificate_info_access_schema():
    from lemur.schemas import CertificateInfoAccessSchema

    input_data = {"includeAIA": True}

    data, errors = CertificateInfoAccessSchema().load(input_data)
    assert not errors
    assert data == {"include_aia": True}

    data, errors = CertificateInfoAccessSchema().dump(data)
    assert not errors
    assert data == input_data


def test_subject_key_identifier_schema():
    from lemur.schemas import SubjectKeyIdentifierSchema

    input_data = {"includeSKI": True}

    data, errors = SubjectKeyIdentifierSchema().load(input_data)
    assert not errors
    assert data == {"include_ski": True}
    data, errors = SubjectKeyIdentifierSchema().dump(data)
    assert not errors
    assert data == input_data


def test_extension_schema(client):
    from lemur.certificates.schemas import ExtensionSchema

    input_data = {
        "keyUsage": {"useKeyEncipherment": True, "useDigitalSignature": True},
        "extendedKeyUsage": {"useServerAuthentication": True},
        "subjectKeyIdentifier": {"includeSKI": True},
    }

    data, errors = ExtensionSchema().load(input_data)
    assert not errors

    data, errors = ExtensionSchema().dump(data)
    assert not errors


def test_certificate_input_schema(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": arrow.get(2018, 11, 9).isoformat(),
        "validityEnd": arrow.get(2019, 11, 9).isoformat(),
        "dnsProvider": None,
        "location": "A Place"
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    assert data["authority"].id == authority.id
    assert data["location"] == "A Place"

    # make sure the defaults got set
    assert data["common_name"] == "test.example.com"
    assert data["country"] == "US"
    assert data["key_type"] == "ECCPRIME256V1"

    assert len(data.keys()) == 20


def test_certificate_input_schema_empty_location(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": arrow.get(2018, 11, 9).isoformat(),
        "validityEnd": arrow.get(2019, 11, 9).isoformat(),
        "dnsProvider": None,
        "location": ""
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    assert len(data.keys()) == 20
    assert data["location"] == ""

    # make sure the defaults got set
    assert data["common_name"] == "test.example.com"
    assert data["country"] == "US"
    assert data["key_type"] == "ECCPRIME256V1"


def test_certificate_input_with_extensions(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "extensions": {
            "keyUsage": {"digital_signature": True},
            "extendedKeyUsage": {
                "useClientAuthentication": True,
                "useServerAuthentication": True,
            },
            "subjectKeyIdentifier": {"includeSKI": True},
            "subAltNames": {
                "names": [{"nameType": "DNSName", "value": "test.example.com"}]
            },
        },
        "dnsProvider": None,
        "keyType": "RSA2048"
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors
    assert data["key_type"] == "RSA2048"


def test_certificate_input_schema_parse_csr(authority, logged_in_admin):
    from lemur.certificates.schemas import CertificateInputSchema

    test_san_dns = "foobar.com"
    extensions = {
        "sub_alt_names": {
            "names": x509.SubjectAlternativeName([x509.DNSName(test_san_dns)])
        }
    }
    csr, private_key = create_csr(
        owner="joe@example.com",
        common_name="ACommonName",
        organization="test",
        organizational_unit="Meters",
        country="NL",
        state="Noord-Holland",
        location="Amsterdam",
        key_type="RSA2048",
        extensions=extensions,
    )

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "csr": csr,
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)

    assert not errors
    for san in data["extensions"]["sub_alt_names"]["names"]:
        assert san.value == test_san_dns

    assert data["key_type"] == "RSA2048"


def test_certificate_out_of_range_date(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityYears": 100,
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors

    input_data["validityStart"] = "2017-04-30T00:12:34.513631"

    data, errors = CertificateInputSchema().load(input_data)
    assert errors

    input_data["validityEnd"] = "2018-04-30T00:12:34.513631"

    data, errors = CertificateInputSchema().load(input_data)
    assert errors


def test_certificate_valid_years(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityYears": 1,
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_valid_dates(client, authority):
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "test.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_cn_admin(client, authority, logged_in_admin):
    """Admin is exempt from CN/SAN domain restrictions."""
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "*.admin-overrides-allowlist.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_allowed_names(client, authority, session, logged_in_user):
    """Test for allowed CN and SAN values."""
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "Names with spaces are not checked",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "extensions": {
            "subAltNames": {
                "names": [
                    {"nameType": "DNSName", "value": "allowed.example.com"},
                    {"nameType": "IPAddress", "value": "127.0.0.1"},
                ]
            }
        },
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors


def test_certificate_inactive_authority(client, authority, session, logged_in_user):
    """Cannot issue certificates with an inactive authority."""
    from lemur.certificates.schemas import CertificateInputSchema

    authority.active = False
    session.add(authority)

    input_data = {
        "commonName": "foo.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors["authority"][0] == "The authority is inactive."


def test_certificate_disallowed_names(client, authority, session, logged_in_user):
    """The CN and SAN are disallowed by LEMUR_ALLOWED_DOMAINS."""
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "*.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "extensions": {
            "subAltNames": {
                "names": [
                    {"nameType": "DNSName", "value": "allowed.example.com"},
                    {"nameType": "DNSName", "value": "evilhacker.org"},
                ]
            }
        },
        "dnsProvider": None,
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors["common_name"][0].startswith(
        "Domain *.example.com does not match allowed domain patterns"
    )
    assert errors["extensions"]["sub_alt_names"]["names"][0].startswith(
        "Domain evilhacker.org does not match allowed domain patterns"
    )


def test_certificate_sensitive_name(client, authority, session, logged_in_user):
    """The CN is disallowed by 'sensitive' flag on Domain model."""
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "commonName": "sensitive.example.com",
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest",
        "validityStart": "2020-01-01T00:00:00",
        "validityEnd": "2020-01-01T00:00:01",
        "dnsProvider": None,
    }
    session.add(Domain(name="sensitive.example.com", sensitive=True))

    data, errors = CertificateInputSchema().load(input_data)
    assert errors["common_name"][0].startswith(
        "Domain sensitive.example.com has been marked as sensitive"
    )


def test_certificate_missing_common_name(client, authority, session, logged_in_user):
    """CN is mandatory unless authority has option cn_optional set to true"""
    from lemur.certificates.schemas import CertificateInputSchema

    input_data = {
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "description": "testtestest"
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert errors["_schema"][0].startswith(
        "Missing common_name"
    )


def test_certificate_only_san_no_cn(session, issuer_plugin, optional_cn_authority, logged_in_user, user):
    """Only SAN is okay with the authority having option cn_optional set to true. Checks new naming with SAN"""
    from lemur.certificates.schemas import CertificateInputSchema
    from lemur.certificates.service import create

    input_data = {
        "owner": "joe@example.com",
        "authority": {"id": optional_cn_authority.id},
        "description": "testtestest",
        "extensions": {
            "subAltNames": {
                "names": [
                    {"nameType": "IPAddress", "value": "192.168.7.1"},
                ]
            }
        }
    }

    data, errors = CertificateInputSchema().load(input_data)
    assert not errors

    csr_text, pkey = create_csr(
        owner=data["owner"],
        key_type=data["key_type"],
        extensions=data["extensions"]
    )
    assert csr_text

    parsed_csr = utils.parse_csr(csr_text)
    san = parsed_csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    assert san
    assert san.value.get_values_for_type(x509.IPAddress)
    assert "192.168.7.1" == str(san.value.get_values_for_type(x509.IPAddress)[0])

    cert = create(
        authority=data["authority"], csr=csr_text, owner=data["owner"], creator=user["user"]
    )

    assert cert
    assert cert.name == "192.168.7.1-LemurTrustUnittestsClass1CA2018-20211108-20211109"


def test_certificate_upload_schema_ok(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "name": "Jane",
        "owner": "pwner@example.com",
        "body": SAN_CERT_STR,
        "privateKey": SAN_CERT_KEY,
        "chain": INTERMEDIATE_CERT_STR,
        "csr": SAN_CERT_CSR,
        "external_id": "1234",
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_minimal(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {"owner": "pwner@example.com", "body": SAN_CERT_STR}
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_long_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "owner": "pwner@example.com",
        "body": SAN_CERT_STR,
        "chain": INTERMEDIATE_CERT_STR + "\n" + ROOTCA_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert not errors


def test_certificate_upload_schema_invalid_body(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "owner": "pwner@example.com",
        "body": "Hereby I certify that this is a valid body",
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {"body": ["Public certificate presented is not valid."]}


def test_certificate_upload_schema_invalid_pkey(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "owner": "pwner@example.com",
        "body": SAN_CERT_STR,
        "privateKey": "Look at me Im a private key!!111",
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {"private_key": ["Private key presented is not valid."]}


def test_certificate_upload_schema_invalid_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {"body": SAN_CERT_STR, "chain": "CHAINSAW", "owner": "pwner@example.com"}
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {"chain": ["Invalid certificate in certificate chain."]}


def test_certificate_upload_schema_wrong_pkey(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "body": SAN_CERT_STR,
        "privateKey": ROOTCA_KEY,
        "chain": INTERMEDIATE_CERT_STR,
        "owner": "pwner@example.com",
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {"_schema": ["Private key does not match certificate."]}


def test_certificate_upload_schema_wrong_chain(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "owner": "pwner@example.com",
        "body": SAN_CERT_STR,
        "chain": ROOTCA_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {
        "_schema": [
            "Incorrect chain certificate(s) provided: 'san.example.org' is not signed by "
            "'LemurTrust Unittests Root CA 2018'"
        ]
    }


def test_certificate_upload_schema_wrong_chain_2nd(client):
    from lemur.certificates.schemas import CertificateUploadInputSchema

    data = {
        "owner": "pwner@example.com",
        "body": SAN_CERT_STR,
        "chain": INTERMEDIATE_CERT_STR + "\n" + SAN_CERT_STR,
    }
    data, errors = CertificateUploadInputSchema().load(data)
    assert errors == {
        "_schema": [
            "Incorrect chain certificate(s) provided: 'LemurTrust Unittests Class 1 CA 2018' is "
            "not signed by 'san.example.org'"
        ]
    }


def test_certificate_revoke_schema():
    from lemur.certificates.schemas import CertificateRevokeSchema

    input = {
        "comments": "testing certificate revoke schema",
        "crl_reason": "cessationOfOperation"
    }
    data, errors = CertificateRevokeSchema().load(input)
    assert not errors

    input["crl_reason"] = "fakeCrlReason"
    data, errors = CertificateRevokeSchema().load(input)
    assert errors == {
        "crl_reason": ['Not a valid choice.']
    }


def test_create_basic_csr(client):
    csr_config = dict(
        common_name="example.com",
        organization="Example, Inc.",
        organizational_unit="Operations",
        country="US",
        state="CA",
        location="A place",
        owner="joe@example.com",
        key_type="RSA2048",
        extensions=dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("test.example.com"),
                        x509.DNSName("test2.example.com"),
                    ]
                )
            )
        ),
    )
    csr, pem = create_csr(**csr_config)

    csr = x509.load_pem_x509_csr(csr.encode("utf-8"), default_backend())
    for name in csr.subject:
        assert name.value in csr_config.values()


def test_csr_empty_san(client):
    """Test that an empty "names" list does not produce a CSR with empty SubjectAltNames extension.

    The Lemur UI always submits this extension even when no alt names are defined.
    """

    csr_text, pkey = create_csr(
        common_name="daniel-san.example.com",
        owner="daniel-san@example.com",
        key_type="RSA2048",
        extensions={"sub_alt_names": {"names": x509.SubjectAlternativeName([])}},
    )

    csr = x509.load_pem_x509_csr(csr_text.encode("utf-8"), default_backend())

    with pytest.raises(x509.ExtensionNotFound):
        csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_csr_disallowed_cn(client, logged_in_user):
    """Domain name CN is disallowed via LEMUR_ALLOWED_DOMAINS."""
    from lemur.common import validators

    request, pkey = create_csr(
        common_name="evilhacker.org", owner="joe@example.com", key_type="RSA2048"
    )
    with pytest.raises(ValidationError) as err:
        validators.csr(request)
    assert str(err.value).startswith(
        "Domain evilhacker.org does not match allowed domain patterns"
    )


def test_csr_disallowed_san(client, logged_in_user):
    """SAN name is disallowed by LEMUR_ALLOWED_DOMAINS."""
    from lemur.common import validators

    request, pkey = create_csr(
        common_name="CN with spaces isn't a domain and is thus allowed",
        owner="joe@example.com",
        key_type="RSA2048",
        extensions={
            "sub_alt_names": {
                "names": x509.SubjectAlternativeName([x509.DNSName("evilhacker.org")])
            }
        },
    )
    with pytest.raises(ValidationError) as err:
        validators.csr(request)
    assert str(err.value).startswith(
        "Domain evilhacker.org does not match allowed domain patterns"
    )


def test_get_name_from_arn(client):
    from lemur.certificates.service import get_name_from_arn

    arn = "arn:aws:iam::11111111:server-certificate/mycertificate"
    assert get_name_from_arn(arn) == "mycertificate"


def test_get_account_number(client):
    from lemur.certificates.service import get_account_number

    arn = "arn:aws:iam::11111111:server-certificate/mycertificate"
    assert get_account_number(arn) == "11111111"


def test_mint_certificate(issuer_plugin, authority):
    from lemur.certificates.service import mint

    cert_body, private_key, chain, external_id, csr = mint(
        authority=authority, csr=CSR_STR
    )
    assert cert_body == SAN_CERT_STR


def test_create_certificate(issuer_plugin, authority, user):
    from lemur.certificates.service import create

    cert = create(
        authority=authority, csr=CSR_STR, owner="joe@example.com", creator=user["user"]
    )
    assert str(cert.not_after) == "2047-12-31T22:00:00+00:00"
    assert str(cert.not_before) == "2017-12-31T22:00:00+00:00"
    assert cert.issuer == "LemurTrustUnittestsClass1CA2018"
    assert (
        cert.name
        == "SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231-AFF2DB4F8D2D4D8E80FA382AE27C2333"
    )

    cert = create(
        authority=authority,
        csr=CSR_STR,
        owner="joe@example.com",
        name="ACustomName1",
        creator=user["user"],
    )
    assert cert.name == "ACustomName1"


def test_reissue_certificate(
    issuer_plugin, crypto_authority, certificate, logged_in_user
):
    from lemur.certificates.service import reissue_certificate
    from lemur.authorities.service import update_options
    from lemur.tests.conf import LEMUR_DEFAULT_ORGANIZATION

    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority
    new_cert = reissue_certificate(certificate)
    assert new_cert
    assert new_cert.key_type == "RSA2048"
    assert new_cert.organization != certificate.organization
    # Check for default value since authority does not have cab_compliant option set
    assert new_cert.organization == LEMUR_DEFAULT_ORGANIZATION
    assert new_cert.description.startswith(f"Reissued by Lemur for cert ID {certificate.id}")

    # update cab_compliant option to false for crypto_authority to maintain subject details
    update_options(crypto_authority.id, '[{"name": "cab_compliant","value":false}]')
    new_cert = reissue_certificate(certificate)
    assert new_cert.organization == certificate.organization


def test_create_csr():
    csr, private_key = create_csr(
        owner="joe@example.com",
        common_name="ACommonName",
        organization="test",
        organizational_unit="Meters",
        country="US",
        state="CA",
        location="Here",
        key_type="RSA2048",
    )
    assert csr
    assert private_key

    extensions = {
        "sub_alt_names": {
            "names": x509.SubjectAlternativeName([x509.DNSName("AnotherCommonName")])
        }
    }
    csr, private_key = create_csr(
        owner="joe@example.com",
        common_name="ACommonName",
        organization="test",
        organizational_unit="Meters",
        country="US",
        state="CA",
        location="Here",
        extensions=extensions,
        key_type="RSA2048",
    )
    assert csr
    assert private_key


def test_import(user):
    from lemur.certificates.service import import_certificate

    cert = import_certificate(
        body=SAN_CERT_STR,
        chain=INTERMEDIATE_CERT_STR,
        private_key=SAN_CERT_KEY,
        creator=user["user"],
    )
    assert str(cert.not_after) == "2047-12-31T22:00:00+00:00"
    assert str(cert.not_before) == "2017-12-31T22:00:00+00:00"
    assert cert.issuer == "LemurTrustUnittestsClass1CA2018"
    assert cert.name.startswith(
        "SAN-san.example.org-LemurTrustUnittestsClass1CA2018-20171231-20471231"
    )

    cert = import_certificate(
        body=SAN_CERT_STR,
        chain=INTERMEDIATE_CERT_STR,
        private_key=SAN_CERT_KEY,
        owner="joe@example.com",
        name="ACustomName2",
        creator=user["user"],
    )
    assert cert.name == "ACustomName2"


@pytest.mark.skip
def test_upload(user):
    from lemur.certificates.service import upload

    cert = upload(
        body=SAN_CERT_STR,
        chain=INTERMEDIATE_CERT_STR,
        private_key=SAN_CERT_KEY,
        owner="joe@example.com",
        creator=user["user"],
    )
    assert str(cert.not_after) == "2040-01-01T20:30:52+00:00"
    assert str(cert.not_before) == "2015-06-26T20:30:52+00:00"
    assert cert.issuer == "Example"
    assert cert.name == "long.lived.com-Example-20150626-20400101-3"

    cert = upload(
        body=SAN_CERT_STR,
        chain=INTERMEDIATE_CERT_STR,
        private_key=SAN_CERT_KEY,
        owner="joe@example.com",
        name="ACustomName",
        creator=user["user"],
    )
    assert "ACustomName" in cert.name


# verify upload with a private key as a str
def test_upload_private_key_str(user):
    from lemur.certificates.service import upload

    cert = upload(
        body=SAN_CERT_STR,
        chain=INTERMEDIATE_CERT_STR,
        private_key=SAN_CERT_KEY,
        owner="joe@example.com",
        name="ACustomName",
        creator=user["user"],
    )
    assert cert


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_certificate_get_private_key(client, token, status):
    assert (
        client.get(
            api.url_for(Certificates, certificate_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_certificate_get(client, token, status):
    assert (
        client.get(
            api.url_for(Certificates, certificate_id=1), headers=token
        ).status_code
        == status
    )


def test_certificate_get_body(client):
    response_body = client.get(
        api.url_for(Certificates, certificate_id=1), headers=VALID_USER_HEADER_TOKEN
    ).json
    assert response_body["serial"] == "211983098819107449768450703123665283596"
    assert response_body["serialHex"] == "9F7A75B39DAE4C3F9524C68B06DA6A0C"
    assert response_body["distinguishedName"] == (
        "L=Earth,"
        "ST=N/A,"
        "C=EE,"
        "OU=Unittesting Operations Center,"
        "O=LemurTrust Enterprises Ltd,"
        "CN=LemurTrust Unittests Class 1 CA 2018"
    )

    # No authority details are provided in this test, no information about being cab_compliant is available.
    # Thus original subject details should be returned.
    assert response_body["country"] == "EE"
    assert response_body["state"] == "N/A"
    assert response_body["location"] == "Earth"
    assert response_body["organization"] == "LemurTrust Enterprises Ltd"
    assert response_body["organizationalUnit"] == "Unittesting Operations Center"


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_certificate_post_update_switches(client, certificate, token, status):
    # negate the current notify/rotation flag and pass it to update POST call to flip the notify/rotation
    toggled_notify = not certificate.notify
    toggled_rotation = not certificate.rotation

    response = client.post(
        api.url_for(Certificates, certificate_id=certificate.id),
        data=json.dumps({"notify": toggled_notify, "rotation": toggled_rotation}),
        headers=token
    )

    assert response.status_code == status
    if status == 200:
        assert response.json.get("notify") == toggled_notify
        assert response.json.get("rotation") == toggled_rotation


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_certificates_update_owner(client, token, status, issuer_plugin, certificate, notification_plugin):
    from lemur.certificates import service as certificate_service
    from lemur.roles import service as role_service
    from lemur.notifications import service as notification_service
    from lemur.tests.factories import NotificationFactory, RoleFactory

    new_cert_owner = "newowner@example.com"

    notification_label = "DEFAULT_" + certificate.owner.split("@")[0].upper() + "_30_DAY"
    notification = notification_service.get_by_label(notification_label)
    if not notification:
        notification = NotificationFactory(label=notification_label)
    certificate.notifications.append(notification)
    owner_role = role_service.get_by_name(certificate.owner)
    if not owner_role:
        owner_role = RoleFactory(name=certificate.owner)
    certificate.roles.append(owner_role)

    assert certificate.owner != new_cert_owner
    assert notification in certificate.notifications
    assert owner_role in certificate.roles
    for role in certificate.roles:
        assert new_cert_owner not in role.name

    response = client.post(
        api.url_for(CertificateUpdateOwner, certificate_id=certificate.id),
        data=json.dumps({"owner": new_cert_owner}),
        headers=token
    )

    assert response.status_code == status
    if status == 200:
        assert response.json.get("owner") == new_cert_owner
        new_cert = certificate_service.get(certificate.id)
        assert new_cert.owner == new_cert_owner

        new_owner_role = role_service.get_by_name(new_cert_owner)
        new_owner_notification = notification_service.get_by_label("DEFAULT_NEWOWNER_30_DAY")

        assert notification not in new_cert.notifications
        assert new_owner_notification in new_cert.notifications
        assert owner_role not in new_cert.roles
        assert new_owner_role in certificate.roles


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_certificate_put(client, token, status):
    assert (
        client.put(
            api.url_for(Certificates, certificate_id=1), data={}, headers=token
        ).status_code
        == status
    )


def test_certificate_put_with_data(client, certificate, issuer_plugin):
    resp = client.put(
        api.url_for(Certificates, certificate_id=certificate.id),
        data=json.dumps(
            {"owner": "bob@example.com", "description": "test", "notify": True}
        ),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    assert len(certificate.notifications) == 3
    assert certificate.roles[0].name == "bob@example.com"
    assert certificate.notify


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 204),
        (VALID_ADMIN_API_TOKEN, 412),
        ("", 401),
    ],
)
def test_certificate_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(Certificates, certificate_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 204),
        (VALID_ADMIN_API_TOKEN, 204),
        ("", 401),
    ],
)
def test_invalid_certificate_delete(client, invalid_certificate, token, status):
    assert (
        client.delete(
            api.url_for(Certificates, certificate_id=invalid_certificate.id),
            headers=token,
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificate_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Certificates, certificate_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_certificates_get(client, token, status):
    assert (
        client.get(api.url_for(CertificatesList), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_certificates_post(client, token, status):
    assert (
        client.post(api.url_for(CertificatesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_put(client, token, status):
    assert (
        client.put(api.url_for(CertificatesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_delete(client, token, status):
    assert (
        client.delete(api.url_for(CertificatesList), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_patch(client, token, status):
    assert (
        client.patch(api.url_for(CertificatesList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificate_credentials_post(client, token, status):
    assert (
        client.post(
            api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificate_credentials_put(client, token, status):
    assert (
        client.put(
            api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificate_credentials_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(CertificatePrivateKey, certificate_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificate_credentials_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(CertificatePrivateKey, certificate_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_upload_get(client, token, status):
    assert (
        client.get(api.url_for(CertificatesUpload), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 400),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_certificates_upload_post(client, token, status):
    assert (
        client.post(api.url_for(CertificatesUpload), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_upload_put(client, token, status):
    assert (
        client.put(api.url_for(CertificatesUpload), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_upload_delete(client, token, status):
    assert (
        client.delete(api.url_for(CertificatesUpload), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_certificates_upload_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(CertificatesUpload), data={}, headers=token
        ).status_code
        == status
    )


def test_sensitive_sort(client):
    resp = client.get(
        api.url_for(CertificatesList) + "?sortBy=private_key&sortDir=asc",
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert "'private_key' is not sortable or filterable" in resp.json["message"]


def test_boolean_filter(client):
    resp = client.get(
        api.url_for(CertificatesList) + "?filter=notify;true",
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    # Also don't crash with invalid input (we currently treat that as false)
    resp = client.get(
        api.url_for(CertificatesList) + "?filter=notify;whatisthis",
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200


def test_issued_cert_count_for_authority(authority):
    from lemur.tests.factories import CertificateFactory
    from lemur.certificates.service import get_issued_cert_count_for_authority

    assert get_issued_cert_count_for_authority(authority) == 0

    # create a few certs issued by the authority
    CertificateFactory(authority=authority, name="test_issued_cert_count_for_authority1")
    CertificateFactory(authority=authority, name="test_issued_cert_count_for_authority2")
    CertificateFactory(authority=authority, name="test_issued_cert_count_for_authority3")

    assert get_issued_cert_count_for_authority(authority) == 3


def test_identify_and_persist_expiring_deployed_certificates():
    from lemur.domains.models import Domain

    """
    This test spins up three local servers, each serving the same default test cert with a non-matching CN/SANs.
    The logic to check if a cert is still deployed ignores certificate validity; all it needs to know is whether
    the certificate currently deployed at the cert's associated domain has the same serial number as the one in
    Lemur's DB. The expiration check is done using the date in Lemur's DB, and is not parsed from the actual deployed
    certificate - so we can get away with using a totally unrelated cert, as long as the serial number matches.
    In this test, the serial number is always the same, since it's parsed from the hardcoded test cert.
    """

    # one non-expiring cert, two expiring certs, one cert that doesn't match a running server,
    # one cert using an excluded domain, and one cert belonging to an excluded owner.
    cert_1 = create_cert_that_expires_in_days(180, domains=[Domain(name='localhost')], owner='testowner1@example.com')
    cert_2 = create_cert_that_expires_in_days(10, domains=[Domain(name='localhost')], owner='testowner2@example.com')
    cert_3 = create_cert_that_expires_in_days(10, domains=[Domain(name='localhost')], owner='testowner3@example.com')
    cert_4 = create_cert_that_expires_in_days(10, domains=[Domain(name='not-localhost')], owner='testowner4@example.com')
    cert_5 = create_cert_that_expires_in_days(10, domains=[Domain(name='abc.excluded.com')], owner='testowner5@example.com')
    cert_6 = create_cert_that_expires_in_days(10, domains=[Domain(name='localhost')], owner='excludedowner@example.com')

    # test certs are all hardcoded with the same body/chain so we don't need to use the created cert here
    cert_file_data = SAN_CERT_STR + INTERMEDIATE_CERT_STR + ROOTCA_CERT_STR + SAN_CERT_KEY
    f = NamedTemporaryFile(suffix='.pem', delete=True)
    try:
        f.write(cert_file_data.encode('utf-8'))
        server_1 = run_server(65521, f.name)
        server_2 = run_server(65522, f.name)
        server_3 = run_server(65523, f.name)
        if not (server_1.is_alive() and server_2.is_alive() and server_3.is_alive()):
            fail('Servers not alive, test cannot proceed')

        for c in [cert_1, cert_2, cert_3, cert_4]:
            assert len(c.certificate_associations) == 1
            for ca in c.certificate_associations:
                assert ca.ports is None
        identify_and_persist_expiring_deployed_certificates(['excluded.com'], ['excludedowner@example.com'], True)
        for c in [cert_1, cert_5, cert_6]:
            assert len(c.certificate_associations) == 1
            for ca in c.certificate_associations:
                assert ca.ports is None  # cert_1 is not expiring, cert_5 is excluded by domain,
                # and cert_6 is excluded by owner, so none of them should be updated
        for c in [cert_4]:
            assert len(c.certificate_associations) == 1
            for ca in c.certificate_associations:
                assert ca.ports == []  # cert_4 is valid but doesn't match so the request runs but the cert isn't found
        for c in [cert_2, cert_3]:
            assert len(c.certificate_associations) == 1
            for ca in c.certificate_associations:
                assert ca.ports == [65521, 65522, 65523]
    finally:
        f.close()  # close file (which also deletes it)


def run_server(port, cert_file_name):
    """Utility method to create a mock server that serves a specific certificate"""

    def start_server():
        server = HTTPServer(('localhost', port), SimpleHTTPRequestHandler)
        server.socket = ssl.wrap_socket(server.socket,
                                        server_side=True,
                                        certfile=cert_file_name,
                                        ssl_version=ssl.PROTOCOL_TLSv1_2)
        server.serve_forever()
        print(f"Started https server on port {port} using cert file {cert_file_name}")

    daemon = threading.Thread(name=f'server_{cert_file_name}', target=start_server)
    daemon.setDaemon(True)  # Set as a daemon so it will be killed once the main thread is dead.
    daemon.start()
    return daemon


def mocked_is_authorized_for_domain(name):
    domain_in_error = "fail.lemur.com"
    if name == domain_in_error:
        raise UnauthorizedError(user="dummy_user", resource=domain_in_error, action="issue_certificate",
                                details="unit test, mocked failure")


@pytest.mark.parametrize(
    "common_name, extensions, expected_error, authz_check_count",
    [
        ("fail.lemur.com", None, True, 1),
        ("fail.lemur.com", dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("test.example.com"),
                        x509.DNSName("test2.example.com"),
                    ]
                )
            )
        ), True, 3),  # CN is checked after SAN
        ("test.example.com", dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("fail.lemur.com"),
                        x509.DNSName("test2.example.com"),
                    ]
                )
            )
        ), True, 1),
        (None, dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("fail.lemur.com"),
                        x509.DNSName("test2.example.com"),
                    ]
                )
            )
        ), True, 1),
        ("pass.lemur.com", None, False, 1),
        ("pass.lemur.com", dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("test.example.com"),
                        x509.DNSName("test2.example.com"),
                    ]
                )
            )
        ), False, 3),
        ("pass.lemur.com", dict(
            sub_alt_names=dict(
                names=x509.SubjectAlternativeName(
                    [
                        x509.DNSName("test.example.com"),
                        x509.DNSName("pass.lemur.com"),
                    ]
                )
            )
        ), False, 2),  # CN repeated in SAN
    ],
)
def test_allowed_issuance_for_domain(common_name, extensions, expected_error, authz_check_count):
    from lemur.certificates.service import allowed_issuance_for_domain

    with patch(
        'lemur.certificates.service.is_authorized_for_domain', side_effect=mocked_is_authorized_for_domain
    ) as wrapper:
        try:
            allowed_issuance_for_domain(common_name, extensions)
            if expected_error:
                assert False, f"UnauthorizedError did not occur, input: CN({common_name}), SAN({extensions})"
        except UnauthorizedError as e:
            if expected_error:
                pass
            else:
                assert False, f"UnauthorizedError occured, input: CN({common_name}), SAN({extensions})"

        assert wrapper.call_count == authz_check_count


def test_send_certificate_expiration_metrics(certificate):
    from lemur.certificates.service import send_certificate_expiration_metrics

    new_cert = create_cert_that_expires_in_days(10)

    success, failure = send_certificate_expiration_metrics()
    assert failure == 0


@pytest.mark.parametrize(
    "cert_expiry, expiry_window, expected_result", [
        (10, None, True),
        (10, 60, True),
        # cert expiry is outside the window
        (70, 60, False)
    ]
)
def test_get_certificates_for_expiration_metrics(certificate, cert_expiry, expiry_window, expected_result):
    from lemur.certificates.service import get_certificates_for_expiration_metrics

    new_cert = create_cert_that_expires_in_days(cert_expiry)
    certs = get_certificates_for_expiration_metrics(expiry_window)

    # check if new_cert is returned in certs list
    assert (new_cert in certs) == expected_result


def test_get_cert_expiry_in_days(certificate):
    from lemur.certificates.service import _get_cert_expiry_in_days
    new_cert = create_cert_that_expires_in_days(10)

    assert _get_cert_expiry_in_days(new_cert.not_after) == 10


def test_query_common_name(session):
    from lemur.tests.factories import CertificateFactory
    from lemur.certificates.service import query_common_name
    from datetime import timedelta

    cn1 = "testcn1.example.org"
    cert_cn1_replaced = CertificateFactory()
    cert_cn1_replaced.cn = cn1
    cert_cn1_valid = CertificateFactory()
    cert_cn1_valid.cn = cn1
    cert_cn1_valid.domains = [Domain(name=cn1)]
    cert_cn1_valid.owner = "owner1@example.org"
    cert_cn1_valid.replaces.append(cert_cn1_replaced)
    cert_cn1_valid2 = CertificateFactory()
    cert_cn1_valid2.cn = cn1
    cert_cn1_valid2.domains = [Domain(name=cn1)]
    cert_cn1_valid2.owner = "owner2@example.org"
    yesterday = arrow.utcnow() + timedelta(days=-1)
    cert_cn1_expired = CertificateFactory()
    cert_cn1_expired.cn = cn1
    cert_cn1_expired.not_after = yesterday
    cert_cn1_revoked = CertificateFactory()
    cert_cn1_revoked.cn = cn1
    cert_cn1_revoked.status = "revoked"

    cn2 = "testcn2.example.org"
    cert_cn2 = CertificateFactory()
    cert_cn2.cn = cn2

    cn1_valid_certs = query_common_name(cn1, {"owner": "", "san": "", "page": "", "count": ""})
    assert len(cn1_valid_certs) == 2

    # since CN is also stored as SAN, count should be the same if filtered using cn1 as SAN
    cn1_san_valid_certs = query_common_name('%', {"owner": "", "san": cn1, "page": "", "count": ""})
    assert len(cn1_san_valid_certs) == 2

    cn1_valid_certs_paged = query_common_name(cn1, {"owner": "", "san": "", "page": 1, "count": 100})
    assert cn1_valid_certs_paged["total"] == 2
    assert len(cn1_valid_certs_paged["items"]) == 2

    cn1_valid_certs_paged_single = query_common_name(cn1, {"owner": "", "san": "", "page": 1, "count": 1})
    assert cn1_valid_certs_paged_single["total"] == 2
    assert len(cn1_valid_certs_paged_single["items"]) == 1

    cn1_owner1_valid_certs = query_common_name(cn1, {"owner": "owner1@example.org", "san": "", "page": "", "count": ""})
    assert len(cn1_owner1_valid_certs) == 1

    cn1_owner1_valid_certs_paged = query_common_name(cn1, {"owner": "owner1@example.org", "san": "", "page": 1, "count": 100})
    assert cn1_owner1_valid_certs_paged["total"] == 1
    assert len(cn1_owner1_valid_certs_paged["items"]) == 1

    cn1_owner2_valid_certs = query_common_name(cn1, {"owner": "owner2@example.org", "san": "", "page": "", "count": ""})
    assert len(cn1_owner2_valid_certs) == 1

    cn1_owner3_valid_certs = query_common_name(cn1, {"owner": "owner3@example.org", "san": "", "page": "", "count": ""})
    assert len(cn1_owner3_valid_certs) == 0

    cn2_valid_certs = query_common_name(cn2, {"owner": "", "san": "", "page": "", "count": ""})
    assert len(cn2_valid_certs) == 1


def test_query_san(session):
    from lemur.tests.factories import CertificateFactory
    from lemur.certificates.service import query_common_name

    san1 = "testsan1.example.org"
    san2 = "testsan2.example.org"

    cert_one_san_valid = CertificateFactory()
    cert_one_san_valid.domains = [Domain(name=san1)]
    cert_one_san_valid.owner = "owner1@example.org"

    cert_two_san_valid = CertificateFactory()
    cert_two_san_valid.domains = [Domain(name=san1), Domain(name=san2)]
    cert_two_san_valid.owner = "owner2@example.org"

    san1_valid_certs = query_common_name('%', {"owner": "", "san": san1, "page": "", "count": ""})
    assert len(san1_valid_certs) == 2

    san1_owner1_valid_certs = query_common_name('%', {"owner": "owner1@example.org", "san": san1, "page": "", "count": ""})
    assert len(san1_owner1_valid_certs) == 1

    san1_valid_certs = query_common_name('%', {"owner": "", "san": san2, "page": "", "count": ""})
    assert len(san1_valid_certs) == 1


def test_reissue_certificate_with_duplicate_destinations_not_allowed(session,
                                                                     logged_in_user,
                                                                     crypto_authority,
                                                                     issuer_plugin,
                                                                     destination_plugin,
                                                                     certificate):
    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority

    destination1 = DestinationFactory()
    destination2 = DestinationFactory()
    certificate.destinations.append(destination1)
    certificate.destinations.append(destination2)
    with pytest.raises(Exception, match='Duplicate destinations for plugin test-destination and account 1234567890 '
                                        'are not allowed'):
        reissue_certificate(certificate)


def test_reissue_certificate_with_duplicate_destinations_allowed(session,
                                                                 logged_in_user,
                                                                 crypto_authority,
                                                                 issuer_plugin,
                                                                 duplicate_allowed_destination_plugin,
                                                                 certificate):
    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority

    destination1 = DuplicateAllowedDestinationFactory()
    destination2 = DuplicateAllowedDestinationFactory()
    certificate.destinations.append(destination1)
    certificate.destinations.append(destination2)
    new_cert = reissue_certificate(certificate)
    assert new_cert
    assert len(new_cert.destinations) == 2
    assert destination1 in new_cert.destinations
    assert destination2 in new_cert.destinations


def test_certificate_update_duplicate_destinations_not_allowed(client, crypto_authority, certificate, issuer_plugin,
                                                               destination_plugin):
    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority

    destination1 = DestinationFactory()
    destination2 = DestinationFactory()
    certificate.destinations.append(destination1)
    certificate.destinations.append(destination2)

    resp = client.put(
        api.url_for(Certificates, certificate_id=certificate.id),
        data=json.dumps(
            certificate_output_schema.dump(certificate).data
        ),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 400
    assert 'Duplicate destinations for plugin test-destination and account 1234567890 are not allowed' \
           in resp.json['message']


def test_certificate_update_duplicate_destinations_allowed(client, crypto_authority, certificate, issuer_plugin,
                                                           duplicate_allowed_destination_plugin):
    from lemur.destinations.schemas import destination_output_schema

    # test-authority would return a mismatching private key, so use 'cryptography-issuer' plugin instead.
    certificate.authority = crypto_authority

    destination1 = DuplicateAllowedDestinationFactory()
    destination2 = DuplicateAllowedDestinationFactory()
    certificate.destinations.append(destination1)
    certificate.destinations.append(destination2)

    resp = client.put(
        api.url_for(Certificates, certificate_id=certificate.id),
        data=json.dumps(
            certificate_output_schema.dump(certificate).data
        ),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert resp.status_code == 200
    resp_cert = resp.json
    assert len(resp_cert['destinations']) == 2
    assert destination_output_schema.dump(destination1).data in resp_cert['destinations']
    assert destination_output_schema.dump(destination2).data in resp_cert['destinations']
