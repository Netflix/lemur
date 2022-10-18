import pytest

from lemur.plugins.lemur_gcp import certificates
from lemur.plugins.lemur_gcp.certificates import get_name, modify_for_gcp

body = """
-----BEGIN CERTIFICATE-----
MIIB7zCCAZagAwIBAgIRAILPQ22P50KYnufSOcyC3xgwCgYIKoZIzj0EAwIwYjES
MBAGA1UEAwwJbG9jYWxob3N0MRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9z
MB4XDTIyMDgzMDE2MzkwN1oXDTIzMDgzMDE2MzkwN1owazEbMBkGA1UEAwwSdGVz
dC5sb2NhbGhvc3QuY29tMRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9zMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FP/xJlvy7jDFRbElv7opDMFF0Tw7jSr
S03Nyh8//spXeNPIvu49uknYsJiMtC19OW8GsH4FXxAMarmLsuUaraMkMCIwIAYD
VR0RAQH/BBYwFIISdGVzdC5sb2NhbGhvc3QuY29tMAoGCCqGSM49BAMCA0cAMEQC
IHDfzhvpCm37SjMbJUY0hbAs+hXYIayNjCZaOvl5gQUEAiAuZ93rbdEZ69Tzd/iN
I/Wm13nhSNDgVeEWbr3BP1ZacQ==
-----END CERTIFICATE-----
"""
cert_chain = """
-----BEGIN CERTIFICATE-----
MIIB7TCCAZSgAwIBAgIQBm3vFdgxR8e2GOGwpR+XTDAKBggqhkjOPQQDAjBiMRIw
EAYDVQQDDAlsb2NhbGhvc3QxFjAUBgNVBAoMDUV4YW1wbGUsIEluYy4xCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3Mw
HhcNMjIwODI2MTkyMjMxWhcNNDIwODI2MTkyMjMxWjBiMRIwEAYDVQQDDAlsb2Nh
bGhvc3QxFjAUBgNVBAoMDUV4YW1wbGUsIEluYy4xCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3MwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQhNX4vrw7MYlenuUfEU5TYvYgjHGeJfULwJeYomzMloKWQ
Msb0aRUWuEJ9STvqDSbHffK/Rm5BXAr328mzpIwRoywwKjAPBgNVHRMBAf8EBTAD
AQH/MBcGA1UdEQEB/wQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNHADBEAiB7
dmVGV4armOiIvo+cyuAN8PLr4mq4ByiVFWl9WQavpAIgRA0leVMbErRrz78EEZZR
aNVFrNhMcvbKB0eqb5VHL90=
-----END CERTIFICATE-----
"""


def test_get_name():
    assert get_name(body) == 'test-localhost-co-exampleinc-0x82cf436d8fe742989ee7d239cc82df18'


@pytest.mark.parametrize(
    ('original_cert_name', 'gcp_cert_name'),
    [
        ("*.test.com", "star-test-com"),
        ("CAPITALIZED.TEST.COM", "capitalized-test-com"),
        ("ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022-",
         "ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022"),
    ]
)
def test_modify_for_gcp(original_cert_name, gcp_cert_name):
    assert modify_for_gcp(original_cert_name) == gcp_cert_name


def test_full_ca():
    assert certificates.full_ca(body, cert_chain) == f"{body}\n{cert_chain}"


def test_get_self_link():
    assert certificates.get_self_link("sandbox", "cert1") == \
           "https://www.googleapis.com/compute/v1/projects/sandbox/global/sslCertificates/cert1"


@pytest.mark.parametrize(
    ("certs", "new_cert", "old_cert", "expected"),
    [
        # new cert does not exist, old cert exists at end
        (["a", "b"], "c", "b", ["a", "c"]),
        # new cert does not exist, old cert does not exist
        (["a"], "c", "b", ["a", "c"]),
        # new cert matches old cert
        (["a", "b"], "b", "b", ["a", "b"]),
        # new cert does exist, old cert does not exist
        (["a", "b", "c"], "c", "d", ["a", "b", "c"]),
        # new cert exists, old cert exists
        (["a", "b"], "a", "b", ["a"]),
    ]
)
def test_calc_certs(certs, new_cert, old_cert, expected):
    assert certificates.calc_diff(certs, new_cert, old_cert) == expected
