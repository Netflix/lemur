import pytest
import requests
import requests_mock
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import UniformResourceIdentifier

from lemur.certificates.verify import verify_string, crl_verify
from lemur.utils import mktempfile
from .vectors import INTERMEDIATE_CERT_STR


def test_verify_simple_cert():
    """Simple certificate without CRL or OCSP."""
    # Verification returns None if there are no means to verify a cert
    res, ocsp_err, crl_err = verify_string(INTERMEDIATE_CERT_STR, "")
    assert res is None


def test_verify_crl_unknown_scheme(cert_builder, private_key):
    """Unknown distribution point URI schemes should be ignored."""
    ldap_uri = "ldap://ldap.example.org/cn=Example%20Certificate%20Authority?certificateRevocationList;binary"
    crl_dp = x509.DistributionPoint(
        [UniformResourceIdentifier(ldap_uri)],
        relative_name=None,
        reasons=None,
        crl_issuer=None,
    )
    cert = cert_builder.add_extension(
        x509.CRLDistributionPoints([crl_dp]), critical=False
    ).sign(private_key, hashes.SHA256(), default_backend())

    with mktempfile() as cert_tmp:
        with open(cert_tmp, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Must not raise exception
        crl_verify(cert, cert_tmp)


def test_verify_crl_unreachable(cert_builder, private_key):
    """Unreachable CRL distribution point results in error."""
    ldap_uri = "http://invalid.example.org/crl/foobar.crl"
    with requests_mock.Mocker() as m:
        m.get(ldap_uri, exc=requests.exceptions.Timeout)
        crl_dp = x509.DistributionPoint(
            [UniformResourceIdentifier(ldap_uri)],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
        cert = cert_builder.add_extension(
            x509.CRLDistributionPoints([crl_dp]), critical=False
        ).sign(private_key, hashes.SHA256(), default_backend())

        with mktempfile() as cert_tmp:
            with open(cert_tmp, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            with pytest.raises(Exception, match="Unable to retrieve CRL:"):
                crl_verify(cert, cert_tmp)
