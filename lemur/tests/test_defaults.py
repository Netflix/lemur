from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from .vectors import SAN_CERT, WILDCARD_CERT, INTERMEDIATE_CERT


def test_cert_get_cn(client):
    from lemur.common.defaults import common_name

    assert common_name(SAN_CERT) == "san.example.org"


def test_cert_sub_alt_domains(client):
    from lemur.common.defaults import domains

    assert domains(INTERMEDIATE_CERT) == []
    assert domains(SAN_CERT) == [
        "san.example.org",
        "san2.example.org",
        "daniel-san.example.org",
    ]


def test_cert_is_san(client):
    from lemur.common.defaults import san

    assert san(SAN_CERT)
    # Wildcard cert has just one SAN record that matches the common name
    assert not san(WILDCARD_CERT)


def test_cert_is_wildcard(client):
    from lemur.common.defaults import is_wildcard

    assert is_wildcard(WILDCARD_CERT)
    assert not is_wildcard(INTERMEDIATE_CERT)


def test_cert_bitstrength(client):
    from lemur.common.defaults import bitstrength

    assert bitstrength(INTERMEDIATE_CERT) == 2048


def test_cert_issuer(client):
    from lemur.common.defaults import issuer

    assert issuer(INTERMEDIATE_CERT) == "LemurTrustUnittestsRootCA2018"


def test_text_to_slug(client):
    from lemur.common.defaults import text_to_slug

    assert text_to_slug("test - string") == "test-string"
    assert text_to_slug("test - string", "") == "teststring"
    # Accented characters are decomposed
    assert text_to_slug("föö bär") == "foo-bar"
    # Melt away the Unicode Snowman
    assert text_to_slug("\u2603") == ""
    assert text_to_slug("\u2603test\u2603") == "test"
    assert text_to_slug("snow\u2603man") == "snow-man"
    assert text_to_slug("snow\u2603man", "") == "snowman"
    # IDNA-encoded domain names should be kept as-is
    assert (
        text_to_slug("xn--i1b6eqas.xn--xmpl-loa9b3671b.com")
        == "xn--i1b6eqas.xn--xmpl-loa9b3671b.com"
    )


def test_create_name(client):
    from lemur.common.defaults import certificate_name
    from datetime import datetime
    from lemur.domains.models import Domain

    assert (
        certificate_name(
            "example.com",
            "Example Inc,",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2015, 5, 12, 0, 0, 0),
            False,
        )
        == "example.com-ExampleInc-20150507-20150512"
    )
    assert (
        certificate_name(
            "example.com",
            "Example Inc,",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2015, 5, 12, 0, 0, 0),
            True,
        )
        == "SAN-example.com-ExampleInc-20150507-20150512"
    )
    assert (
        certificate_name(
            "xn--mnchen-3ya.de",
            "Vertrauenswürdig Autorität",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2015, 5, 12, 0, 0, 0),
            False,
        )
        == "xn--mnchen-3ya.de-VertrauenswurdigAutoritat-20150507-20150512"
    )
    assert (
        certificate_name(
            "selfie.example.org",
            "<selfsigned>",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2025, 5, 12, 13, 37, 0),
            False,
        )
        == "selfie.example.org-selfsigned-20150507-20250512"
    )
    assert (
        certificate_name(
            "selfie.example.org",
            "<selfsigned>",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2025, 5, 12, 13, 37, 0),
            False,
            domains=[Domain(name='san-example')],
        )
        == "selfie.example.org-selfsigned-20150507-20250512"
    )
    assert (
        certificate_name(
            "",
            "<selfsigned>",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2025, 5, 12, 13, 37, 0),
            False,
            domains=[Domain(name='san-example')],
        )
        == "san-example-selfsigned-20150507-20250512"
    )
    assert (
        certificate_name(
            "",
            "<selfsigned>",
            datetime(2015, 5, 7, 0, 0, 0),
            datetime(2025, 5, 12, 13, 37, 0),
            True,
            domains=[Domain(name='san1'), Domain(name='san2')],
        )
        == "SAN-san1-selfsigned-20150507-20250512"
    )


def test_issuer(client, cert_builder, issuer_private_key):
    from lemur.common.defaults import issuer

    assert issuer(INTERMEDIATE_CERT) == "LemurTrustUnittestsRootCA2018"

    # We need to override builder's issuer name
    cert_builder._issuer_name = None
    # Unicode issuer name
    cert = cert_builder.issuer_name(
        x509.Name(
            [x509.NameAttribute(x509.NameOID.COMMON_NAME, "Vertrauenswürdig Autorität")]
        )
    ).sign(issuer_private_key, hashes.SHA256(), default_backend())
    assert issuer(cert) == "VertrauenswurdigAutoritat"

    # Fallback to 'Organization' field when issuer CN is missing
    cert = cert_builder.issuer_name(
        x509.Name(
            [x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "No Such Organization")]
        )
    ).sign(issuer_private_key, hashes.SHA256(), default_backend())
    assert issuer(cert) == "NoSuchOrganization"

    # Missing issuer name
    cert = cert_builder.issuer_name(x509.Name([])).sign(
        issuer_private_key, hashes.SHA256(), default_backend()
    )
    assert issuer(cert) == "<unknown>"


def test_issuer_selfsigned(selfsigned_cert):
    from lemur.common.defaults import issuer

    assert issuer(selfsigned_cert) == "<selfsigned>"
