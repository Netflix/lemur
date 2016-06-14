# coding=utf-8
import arrow
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionOID, Extension, SubjectAlternativeName, DNSName, IPAddress
import ipaddress

from lemur.utils import mktemppath

PRIVATE_KEY_STR = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsXn+QZRATxryRmGXI4fdI+0a2oBwuVh8fC/9bcqX6c5eDmgc
rj6esmc1hpIFxMM3DvkFXX6xISkU6B5fmYDEGZLi7NvcXF3+EoA/SCkP1MFlvqhn
EvNhb0t1fBLs0i/0gfTS/FHBZY1ekHisd/sUetCDZ7F11RxMwws0Oc8bl7j1TpRc
awXFAsh/aWwQOwFeyWU7TtZeAE7sMyWXInBg37tKk1wlv+mN+27WijI091+amkVy
zIV6mA5OHfqbjuqV8uQflN8jE244Qr7shtSk7LpBpWf0M6dC7dXbuUctHFhqcDjy
3IRUl+NisKRoMtq+a0uehfmpFNSUD7F4gdUtSwIDAQABAoIBAGITsZ+aBuPwVzzv
x286MMoeyL1BR4oVzU1v09Rtpf/uLGo3vMnKDzc19A12+rseynl6wi1FyysxIb2Y
s2oID9a2JrOQWLmus66TsuT01CvV6J0xQSzm1MyFXdqANuF84NlEa6hGoeK1+jFK
jr0LQukP+9484oovxnfu5CCiRHRWNZmeuekuYhI1SJf343Tr6jwvyr6KZpnIy0Yt
axuuIZdCfY9ZV2vFG89GwwgwVQrhf14Kv5vBMZrNh1lRGsr0Sqlx5cGkPRAy90lg
HjrRMogrtXr3AR5Pk2qqAYXzZBU2EFhJ3k2njpwOzlSj0r0ZwTmejZ89cco0sW5j
+eQ6aRECgYEA1tkNW75fgwU52Va5VETCzG8II/pZdqNygnoc3z8EutN+1w8f6Tr+
PdpKSICW0z7Iq4f5k/4wrA5xw1vy5RBMH0ZP29GwHTvCPiTBboR9vWvxQvZn1jb9
wvKa0RxE18KcF0YIyTnZMubkA17QTFlvCNyZg0iCqeyFYPyqVE+R4AkCgYEA03h1
XrqECZDDbG9HLUdGbkZNk4VzTcF6dQ3GAPY8M/H7rw5BbvH0RZLOrzl46DDVzKTg
B1VOReAHsxBKFdkqeq1A99CLDow6vHTIEG8DwxkA7/2QPkt8MybwdApUyYnQh5/v
CxwkRt4Mm+EiYfn5iyL8yI+vaQSRToVO/3BND7MCgYAJQSpBJG8qzqPSR9kN1zRo
5/N60ULfSGUbV7U8rJNAlPGmw+EFA+SFt4xxmRBmIxMzyFSo2k8waiLeXmyVD2Go
CzhPaLXkXHmegajPYOelrCulTcXlRVMi/Z5LmaMhhCGDIyInwNUpSybROllQoJ2W
zSHTtODj/usz5U5U+WR4OQKBgHQRosI6t2wUo96peTS18UdnmP7GeZINBuymga5X
eJW+VLkxpuKBNOTW/lCYx+8Rlte7CyebP9oEa9VxtGgniTRKUeVy9lAm0bpMkt7K
QBNebvBKiVhX0DS3Q7U9UmpIFUfLlcXQTW0ERYFtYZTLQpeGvZ5LlyiaFDM34jM7
7WAXAoGANDPJdQLEuimCOAMx/xoecNWeZIP6ieB0hVBrwLNxsaZlkn1KodUMuvla
VEowbtPRdc9o3VZRh4q9cEakssTvOD70hgUZCFcMarmc37RgRvvD2fsZmDZF6qd3
QfHplREs9F0sW+eiirczG7up4XL+CA162TtZxW+2GAiQhwhE5jA=
-----END RSA PRIVATE KEY-----
"""

EXTERNAL_VALID_STR = b"""
-----BEGIN CERTIFICATE-----
MIID2zCCAsOgAwIBAgICA+0wDQYJKoZIhvcNAQELBQAwgZcxCzAJBgNVBAYTAlVT
MRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlMb3MgR2F0b3MxDTALBgNV
BAMMBHRlc3QxFjAUBgNVBAoMDU5ldGZsaXgsIEluYy4xEzARBgNVBAsMCk9wZXJh
dGlvbnMxIzAhBgkqhkiG9w0BCQEWFGtnbGlzc29uQG5ldGZsaXguY29tMB4XDTE1
MTEyMzIxNDIxMFoXDTE1MTEyNjIxNDIxMFowcjENMAsGA1UEAwwEdGVzdDEWMBQG
A1UECgwNTmV0ZmxpeCwgSW5jLjETMBEGA1UECwwKT3BlcmF0aW9uczELMAkGA1UE
BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCUxvcyBHYXRvczCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALF5/kGUQE8a8kZhlyOH3SPt
GtqAcLlYfHwv/W3Kl+nOXg5oHK4+nrJnNYaSBcTDNw75BV1+sSEpFOgeX5mAxBmS
4uzb3Fxd/hKAP0gpD9TBZb6oZxLzYW9LdXwS7NIv9IH00vxRwWWNXpB4rHf7FHrQ
g2exddUcTMMLNDnPG5e49U6UXGsFxQLIf2lsEDsBXsllO07WXgBO7DMllyJwYN+7
SpNcJb/pjftu1ooyNPdfmppFcsyFepgOTh36m47qlfLkH5TfIxNuOEK+7IbUpOy6
QaVn9DOnQu3V27lHLRxYanA48tyEVJfjYrCkaDLavmtLnoX5qRTUlA+xeIHVLUsC
AwEAAaNVMFMwUQYDVR0fBEowSDBGoESgQoZAaHR0cDovL3Rlc3QuY2xvdWRjYS5j
cmwubmV0ZmxpeC5jb20vdGVzdERlY3JpcHRpb25DQVJvb3QvY3JsLnBlbTANBgkq
hkiG9w0BAQsFAAOCAQEAiHREBKg7zhlQ/N7hDIkxgodRSWD7CVbJGSCdkR3Pvr6+
jHBVNTJUrYqy7sL2pIutoeiSTQEH65/Gbm30mOnNu+lvFKxTxzof6kNYv8cyc8sX
eBuBfSrlTodPFSHXQIpOexZgA0f30LOuXegqzxgXkKg+uMXOez5Zo5pNjTUow0He
oe+V1hfYYvL1rocCmBOkhIGWz7622FxKDawRtZTGVsGsMwMIWyvS3+KQ04K8yHhp
bQOg9zZAoYQuHY1inKBnA0II8eW0hPpJrlZoSqN8Tp0NSBpFiUk3m7KNFP2kITIf
tTneAgyUsgfDxNDifZryZSzg7MH31sTBcYaotSmTXw==
-----END CERTIFICATE-----
"""


def test_export_certificate_to_jks(app):
    from lemur.plugins.base import plugins
    p = plugins.get('java-export')
    options = {'passphrase': 'test1234'}
    raw = p.export(EXTERNAL_VALID_STR, "", PRIVATE_KEY_STR, options)
    assert raw != b""


def test_openssl_certificate(app):
    from lemur.authorities.models import Authority
    from lemur.plugins.base import plugins
    p = plugins.get('openssl-issuer')
    ca_options = {
        "caDN": {
            "country": "US",
            "state": "OR",
            "location": "Portland",
            "organization": "ExampleInc",
            "organizationalUnit": "Security",
            "commonName": "Authority"
        },
        "validityStart": "2015-06-11T07:00:00.000Z",
        "validityEnd": "2015-06-13T07:00:00.000Z",
        "extensions": {
            "subAltNames": {
                "names": ['DNS:example.com']
            }
        },
        "caSigningAlgo": "sha256",
        "keyType": "RSA4096",

        "caSensitivity": "medium",

        # These get consumed in authority/service.py, but are here for completeness
        "pluginName": "openssl-issuer",
        "caName": "DoctestCA",
        "caType": "root",
        "caDescription": "Example CA",
        "ownerEmail": "jimbob@example.com",
        "creator": "lemur@example.com"
    }
    options = {
        "criticalCaExtension": True,
        "country": u'US',
        "state": u'CA',
        "location": u'A Place',
        "organization": u'ExampleInc.',
        "organizationalUnit": u'Operations',

        "owner": 'bob@example.com',
        "description": u'test',
        "authority": {
            'name': 'DoctestCA'
        },
        "extensions": {
            "subAltNames": {
                "names": [{
                    'nameType': 'DNSName',
                    'value': u'example.com'
                }, {
                    'nameType': 'IPAddress',
                    'value': u'127.0.0.1'
                }]
            },
            "extendedKeyUsage": {
                "isCritical": True,
                "clientAuth": True
            },
            "subjectKeyIdentifier": {
                "includeSKI": True,
                "isCritical": True
            },
            "authorityKeyIdentifier": {
                "isCritical": True
            },
            "keyUsage": {
                "digitalSignature": True,
                "contentCommitment": False,
                "keyEncipherment": True,
                "dataEncipherment": False,
                "keyAgreement": False,
                "keyCertSign": False,
                "crlSign": False,
                "encipherOnly": False,
                "decipherOnly": False,
                "isCritical": False
            }
        },
        "commonName": u'test',
        "validityStart": '2015-06-05T07:00:00.000Z',
        "validityEnd": '2015-06-16T07:00:00.000Z',
    }

    with mktemppath() as ca_temp:
        app.config['OPENSSL_DIR'] = ca_temp
        root, intermediate, roles = p.create_authority(ca_options)

        from lemur.certificates.service import create_csr

        options['authority'] = Authority(unicode(ca_options['caName']), unicode(ca_options['ownerEmail']), 'openssl-issuer', root)
        csr, private_key_pem = create_csr(options, root)
        cert, root_ca = p.create_certificate(csr, options)

    assert root == root_ca

    assert roles == []
    assert intermediate == ""
    ca_cert = x509.load_pem_x509_certificate(str(root_ca), default_backend())
    cert = x509.load_pem_x509_certificate(str(cert), default_backend())

    assert cert.not_valid_before == arrow.get(options['validityStart']).naive
    assert cert.not_valid_after == arrow.get(options['validityEnd']).naive

    assert isinstance(cert.public_key(), RSAPublicKey)
    assert cert.issuer == x509.load_pem_x509_certificate(str(root_ca), default_backend()).subject
    assert cert.subject == x509.load_pem_x509_csr(csr, default_backend()).subject
    assert cert.signature_hash_algorithm.name == 'sha256'
    assert cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME) == Extension(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True, value=SubjectAlternativeName([
            DNSName(u'example.com'),
            IPAddress(ipaddress.ip_address(u'127.0.0.1'))
        ]))

    assert cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE) == Extension(
        ExtensionOID.EXTENDED_KEY_USAGE, critical=True,
        value=x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]))

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    assert cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER) == Extension(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=True,
        value=x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()))

    assert cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER) == Extension(
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=True,
        value=x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()))

    assert cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE) == Extension(
        ExtensionOID.KEY_USAGE, critical=False,
        value=x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                            data_encipherment=False, key_agreement=False, key_cert_sign=False,
                            crl_sign=False, encipher_only=False, decipher_only=False))
