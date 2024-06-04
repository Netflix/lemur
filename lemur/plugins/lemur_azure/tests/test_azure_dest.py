import os
import unittest
from unittest.mock import patch, ANY

from flask import Flask

# mock certificate to test the upload function code
test_server_cert = """-----BEGIN CERTIFICATE-----
MIIDsDCCApigAwIBAgIJAIezI4YBdaH5MA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNV
BAYTAkFUMQ8wDQYDVQQHDAZWaWVubmExEDAOBgNVBAoMB1NpcmZlcmwxETAPBgNV
BAMMCExvY2FsIENBMSEwHwYJKoZIhvcNAQkBFhJzaXJmZXJsQGdpdGh1Yi5jb20w
HhcNMjEwNzI0MDM1MDIzWhcNMjIxMjA2MDM1MDIzWjBnMQswCQYDVQQGEwJBVDEP
MA0GA1UEBwwGVmllbm5hMRAwDgYDVQQKDAdTaXJmZXJsMSEwHwYJKoZIhvcNAQkB
FhJzaXJmZXJsQGdpdGh1Yi5jb20xEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALR59JM38ltmUDAjQiohKjsB/xkRM86P
ZlsKlL78yTA/XRbrIHDq+88InQajr+R4sq26MmCaAbHBuwn7RCVh2o/letI14WBL
wvYIk1RGxwIFR2nNkQfTMfweK3aHLiL1714pW3cZbGgqGNmP4V5BQLI4eMDu6I9O
WmGWL+HDJsn7ug55aNBV8qxiYIzAQm87bqbBBHbB6ht98SjVPG9kYT4hdxmaQ0lo
eb+hJ6LKcwEN6shyz3bWQ4p2ngglOYQ+D9SNxOH6GHAh72jQr3Pz0iU49D6HUOGg
QXKzV4nl2JFsA+nd8swoHhqmNMAvNgjv5ydaRFwWDdCiyhT8PNGOeFECAwEAAaNg
MF4wHwYDVR0jBBgwFoAUf09uS3ulWhvipHzUkEVskyhfAUcwCQYDVR0TBAIwADAL
BgNVHQ8EBAMCBPAwIwYDVR0RBBwwGoINbXlleGFtcGxlLmNvbYIJbG9jYWxob3N0
MA0GCSqGSIb3DQEBCwUAA4IBAQBS/7o0fMhDX2k0dc5S8cVxBhg8BPVqas99E8g3
bDKnFcUdv4KTVgdYRbQ+o8DMkWZVDwyRDs5f2v9dyWtMk33jtxjs8UTXCmIhNgLg
oSd+GXhOxThRj9euiyP/NA0JbCdrv4z5UEWZ2+U+lsLALoXBZqQAgDpZNggsujqn
o0BydDBcgoQtQ3w5e9k5Upah6f+X0ZryXQemC/BnjKSdXipkcg295WyV780jTQV1
9+NK9wF8ED74VGLaqAHjTT2UmVfiyPs7kxU+KqYzLfl2GL49RDcf4V06q5pr/JmR
tXwUxRyH8L1hRMfyCE/35EhVTmPdc3lRaPXROD1gtuRDEQIb
-----END CERTIFICATE-----"""

test_server_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtHn0kzfyW2ZQMCNCKiEqOwH/GREzzo9mWwqUvvzJMD9dFusg
cOr7zwidBqOv5HiyrboyYJoBscG7CftEJWHaj+V60jXhYEvC9giTVEbHAgVHac2R
B9Mx/B4rdocuIvXvXilbdxlsaCoY2Y/hXkFAsjh4wO7oj05aYZYv4cMmyfu6Dnlo
0FXyrGJgjMBCbztupsEEdsHqG33xKNU8b2RhPiF3GZpDSWh5v6EnospzAQ3qyHLP
dtZDinaeCCU5hD4P1I3E4foYcCHvaNCvc/PSJTj0PodQ4aBBcrNXieXYkWwD6d3y
zCgeGqY0wC82CO/nJ1pEXBYN0KLKFPw80Y54UQIDAQABAoIBAExy0JBABbCD0Xni
pZdU/x+Jw/ZpXAmmotPz0nhoegyu+o7HwLE0SMA1RNbYJZzhJ8cBdW+ILSmQB9u9
jOtM3RlROsqqujJhRU+U6Futs4T+mXaO9l1bL/Q9D2og7wEuLlwzpqP3p/0jv+0A
zpVvjKkx1KzdRrPVm+F0jgnS8a5i9eUH38HzisdC/2Zp1N3Qqszuq7Svqetm/VR5
Kd6G/0zXcEWk8C/dTLvBmTx1iWraDteB+L/tDbOoi7GuKeJLNNFA8gtTJGj01MIO
Yauq9aLimndi/+BPN9vLRJiNLV/yFb5o4O7SDn9Zak5DnP8V1jOkyzRMCT98UgWA
qpGr8XECgYEA4dkJOePvJxT1Ydoh2uhkqiLmNYWRfutdhwp9qPXE+L640Hnl3G0j
VZ4NRyKuXheDr99PCMfD9QXmOXBSe32Pq1AXBwgr047dApqWMXe1tgU40TwQ2Lrk
B3+XONs5OqR7QlXkuM2M3SdUfbRVSKgi/vy8G9dHtlDCWgsdRqY5m/0CgYEAzJI6
UBX4ONBHX8A/ATK+FcUe4qU1jwp1FInAGXLren/rG3zv++IAXHS8FUQGJ2g7ENYw
7tOJEMXZuDitJmRAbKWI2ZrwybAnJrV3n9sOvr1WNShjBMSnXZmhvJ8vI8HOkx19
M9ZaujqTOBF3zFJS96nbaMrSvEb5cR5+RdTPW+UCgYEAlnGE+9MiE96aNryfoLr9
k3f78dsvuGQAwVvzqQFOXIRviDArNlJdH0NRhPlNPdBcIGOYujiYCDgNzGVODITv
lyaasEx5JUwdXQas1fbwTHfeCUMB1d1o2LXdfjpKPQ4kLWQaICCMnST9216tEOEv
rruccs9NLd1OGb0dm1pPNeECgYBZTHun+e8g3cpKQeE+5KeVWTbiOLvodOgmzvrM
IR4pmy1GEoOvsDf4I/z2S3tkOFuQPe+eUTjD2ZnwkM0EtT5qLthOJRR29i4g95YA
cd894+h9y+NtcWqdsTKo49PwB+nkzjqZJjj0kh0xnG5vAoC1G7BrTh4vkcvRVT5J
vVvHAQKBgQC6499cVGtK/I1QsyqGKOq2IjwSWZTpSwnhPDQur1TT8P1BwGGirFFa
nl3mjmPSwbFiOUofgwiHvadTkHyC2shsX3MHGiGXe7cfr98Vw9i+XxpeAUeWAwIU
ja+4tDNMH5MBy6D51R9zzBsY4u8AKSZf7Is78Mnyn21okKGJcjBSuw==
-----END RSA PRIVATE KEY-----"""

test_ca_cert = """-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIJAKF8G3Kk9+j9MA0GCSqGSIb3DQEBCwUAMGYxCzAJBgNV
BAYTAkFUMQ8wDQYDVQQHDAZWaWVubmExEDAOBgNVBAoMB1NpcmZlcmwxETAPBgNV
BAMMCExvY2FsIENBMSEwHwYJKoZIhvcNAQkBFhJzaXJmZXJsQGdpdGh1Yi5jb20w
HhcNMjEwNzI0MDM0MzQ4WhcNMjUwNzIzMDM0MzQ4WjBmMQswCQYDVQQGEwJBVDEP
MA0GA1UEBwwGVmllbm5hMRAwDgYDVQQKDAdTaXJmZXJsMREwDwYDVQQDDAhMb2Nh
bCBDQTEhMB8GCSqGSIb3DQEJARYSc2lyZmVybEBnaXRodWIuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRoDAbrqHPVGEVCR4YdurNGo4CFPXHbo
/X/aWCKmKo6h31Raq8nI93V0pJEdE8EHjcOn52e3FrPmaIX7LusNH/hHgSehvgAv
itHfc5dydSr7Je4Vq/K9z8rQSxpjow670c5kINpMNflyMk7vdox14c7yfKQbNE5B
kRy96JlLczcr3BCbkXNTV4IZvdK/IJLSwp0B1ctEODno4bZ9+VXyoP0egNpBbNch
q9Ej1msemEFL2Ez8WCK4xGIByBc4pCt+3QxH0tZ9qatBns+hE1rse6fYzlmP/bn6
9bWbyeDPw0Y7uK2so1mpraCnqeNRhptTMyyaJHKAlo8M4kt7VC4pXwIDAQABo1Aw
TjAdBgNVHQ4EFgQUf09uS3ulWhvipHzUkEVskyhfAUcwHwYDVR0jBBgwFoAUf09u
S3ulWhvipHzUkEVskyhfAUcwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEADwGur0q858s8eBak/qh4omlZySEzY6mHgNSbBAyBx9BTzTkuSPOP8Zola5m5
nwUv6iLU5spTMcmYhJkL7RB6b47kQK4Bx79A5Vr1db/wcsartrytOCICNgI4wyHG
abYHAXG/fVggzOqo0GUgg2xiUJ554Zely9MySAWsttD8ju3zZdcnWaP1VG6r75w5
X4OJSL6Q/vqLehA8MOjORj3EprM4dv/SixqdTi4hVbkIv+M8vgZTd04O8S98oghl
Q1eMutMqf45yvSgVIr7SHkh2a+S4E7RjkH9pDE+8MQVTiSSPH5ZgEp7FveK4GkfW
Qils0nQFsH1VujvoF9Y04MAgZw==
-----END CERTIFICATE-----"""


class TestAzureDestination(unittest.TestCase):
    def setUp(self):
        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask("lemur_test_azure_dest")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("azure.keyvault.certificates.CertificateClient.import_certificate")
    def test_upload(self, import_certificate_mock):
        from lemur.plugins.lemur_azure.plugin import AzureDestinationPlugin

        subject = AzureDestinationPlugin()

        name = "Test_Certificate"
        body = test_server_cert
        private_key = test_server_key
        cert_chain = test_ca_cert

        def _assert_certificate_imported():
            import_certificate_mock.assert_called_with(
                certificate_name="localhost-Sirferl-RSA2048",
                certificate_bytes=ANY,
                enabled=True,
                policy=ANY,
                tags={"lemur.managed": "true"},
            )

        with self.subTest(case="upload cert using azureApp auth method"):
            options = [
                {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
                {"name": "azureTenant", "value": "mockedTenant"},
                {"name": "azureAppID", "value": "mockedAPPid"},
                {"name": "azurePassword", "value": "norealPW"},
                {"name": "authenticationMethod", "value": "azureApp"},
            ]
            subject.upload(name, body, private_key, cert_chain, options)
            _assert_certificate_imported()

        with self.subTest(case="upload cert using hashicorpVault auth method"):
            options = [
                {"name": "azureKeyVaultUrl", "value": "https://couldbeanyvalue.com"},
                {"name": "azureTenant", "value": "mockedTenant"},
                {"name": "authenticationMethod", "value": "hashicorpVault"},
                {"name": "hashicorpVaultRoleName", "value": "mockedRole"},
                {"name": "hashicorpVaultMountPoint", "value": "azure"},
            ]
            subject.upload(name, body, private_key, cert_chain, options)
            _assert_certificate_imported()
