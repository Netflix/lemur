import pytest
from unittest import mock
from lemur.plugins.lemur_gcp.plugin import GCPDestinationPlugin

name = "ssl-test-localhost-com-localhost-2022-08-30"
token = "ya29.c.b0AXv0zTN36HtXN2cJolg9tAj0vGAOT29FF-WNxQzvPu"
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
private_key = """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH/TlH1MLEwUgPpZqd1EP3+9q792r7GsmecRQe6CknV4oAoGCCqGSM49
AwEHoUQDQgAEVHkf6rYbpV1M7bPMFSbNxC6iHWm0HdvLbaHIjh6FD9O4asxa5TOs
8Z8Lbg3hTUgFamznF34J3oYfEjgTxEO40Q==
-----END EC PRIVATE KEY-----
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

SUCCESS_INSERT_RESPONSE = {
    'kind': 'compute#operation',
    'id': '4927389014336055823',
    'name': 'operation-1661211870499-5e6dd077012f4-9b6e5e0d-ddfc98d2',
    'operationType': 'insert',
    'targetLink': 'https://www.googleapis.com/compute/v1/projects/testubg-sandbox/global/sslCertificates/test-cert-1234',
    'targetId': '8919843282434501135',
    'status': 'RUNNING',
    'user': 'lemur-test@test.iam.gserviceaccount.com',
    'progress': 0,
    'insertTime': '2022-08-22T16:44:32.218-07:00',
    'startTime': '2022-08-22T16:44:32.231-07:00',
}

options = [
    {
        'name': 'projectID',
        'type': 'str',
        'required': True,
        'value': 'lemur-test'
    },
    {
        'name': 'authenticationMethod',
        'type': 'str',
        'required': True,
        'value': 'vault',
    }]


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin.get_option", return_value="lemur-test")
@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._get_gcp_credentials", return_value=token)
@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._insert_gcp_certificate", return_value=SUCCESS_INSERT_RESPONSE)
def test_upload(mock_ssl_certificates, mock_credentials, mock_gcp_account_id):

    assert GCPDestinationPlugin().upload(
        name,
        body,
        private_key,
        cert_chain,
        options) == SUCCESS_INSERT_RESPONSE

    ssl_certificate_body = {
        "name": name,
        "certificate": GCPDestinationPlugin()._full_ca(body, cert_chain),
        "description": "",
        "private_key": private_key,
    }

    # assert our mocks are being called with the params we expect
    mock_ssl_certificates.assert_called_with('lemur-test', ssl_certificate_body, token)
    mock_credentials.assert_called_with(options)
    mock_gcp_account_id.get_option(options)


@mock.patch("lemur.plugins.lemur_gcp.plugin.GCPDestinationPlugin._get_gcp_credentials_from_vault", return_value="ya29.c.b0AXv0zTN36HtXN2cJolg9tAj0vGAOT29FF-WNxQzvPu")
def test_get_gcp_credentials(mock_get_gcp_credentials_from_vault):

    assert GCPDestinationPlugin()._get_gcp_credentials(options) == token

    mock_get_gcp_credentials_from_vault.assert_called_with(options)


def test_certificate_name():
    assert GCPDestinationPlugin()._certificate_name(body) == 'ssl-test-localhost-com-localhost-2022-08-30'


@pytest.mark.parametrize(
    ('original_cert_name', 'gcp_cert_name'),
    [
        ("*.test.com", "star-test-com"),
        ("CAPITALIZED.TEST.COM", "capitalized-test-com"),
        ("ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022-", "ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022"),
        (
            "this.is.a.long.certificate.name.that.should.get.cut.off.after.63.characters.test.com",
            "this-is-a-long-certificate-name-that-should-get-cut-off-after-6"
        )
    ]
)
def test_modify_cert_name_for_gcp(original_cert_name, gcp_cert_name):
    assert GCPDestinationPlugin()._modify_cert_name_for_gcp(original_cert_name) == gcp_cert_name


def test_full_ca():
    assert GCPDestinationPlugin()._full_ca(body, cert_chain) == f"{body}\n{cert_chain}"
