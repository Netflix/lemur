import pytest

from lemur.tests.vectors import (
    SAN_CERT,
    SAN_CERT_STR,
    INTERMEDIATE_CERT,
    ROOTCA_CERT,
    EC_CERT_EXAMPLE,
    ECDSA_PRIME256V1_CERT,
    ECDSA_SECP384r1_CERT,
    ECDSA_SECP384r1_CERT_STR,
    DSA_CERT,
    CERT_CHAIN_PKCS7_PEM,
    ACME_CHAIN_LONG_STR,
    ACME_CHAIN_X1_STR
)


def test_get_key_type_from_ec_curve():
    from lemur.common.utils import get_key_type_from_ec_curve

    assert get_key_type_from_ec_curve("secp256r1") == "ECCPRIME256V1"


def test_generate_private_key():
    from lemur.common.utils import generate_private_key

    assert generate_private_key("RSA2048")
    assert generate_private_key("RSA4096")
    assert generate_private_key("ECCPRIME192V1")
    assert generate_private_key("ECCPRIME256V1")
    assert generate_private_key("ECCSECP192R1")
    assert generate_private_key("ECCSECP224R1")
    assert generate_private_key("ECCSECP256R1")
    assert generate_private_key("ECCSECP384R1")
    assert generate_private_key("ECCSECP521R1")
    assert generate_private_key("ECCSECP256K1")
    assert generate_private_key("ECCSECT163K1")
    assert generate_private_key("ECCSECT233K1")
    assert generate_private_key("ECCSECT283K1")
    assert generate_private_key("ECCSECT409K1")
    assert generate_private_key("ECCSECT571K1")
    assert generate_private_key("ECCSECT163R2")
    assert generate_private_key("ECCSECT233R1")
    assert generate_private_key("ECCSECT283R1")
    assert generate_private_key("ECCSECT409R1")
    assert generate_private_key("ECCSECT571R2")

    with pytest.raises(Exception):
        generate_private_key("LEMUR")


def test_get_authority_key():
    """test get authority key function"""
    from lemur.common.utils import get_authority_key

    test_cert = """-----BEGIN CERTIFICATE-----
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
KFfxwrO1
-----END CERTIFICATE-----"""
    authority_key = get_authority_key(test_cert)
    assert authority_key == "feacb541be81771293affa412d8dc9f66a3ebb80"


def test_is_selfsigned(selfsigned_cert):
    from lemur.common.utils import is_selfsigned

    assert is_selfsigned(selfsigned_cert) is True
    assert is_selfsigned(SAN_CERT) is False
    assert is_selfsigned(INTERMEDIATE_CERT) is False
    # Root CA certificates are also technically self-signed
    assert is_selfsigned(ROOTCA_CERT) is True
    assert is_selfsigned(EC_CERT_EXAMPLE) is False

    # selfsigned certs
    assert is_selfsigned(ECDSA_PRIME256V1_CERT) is True
    assert is_selfsigned(ECDSA_SECP384r1_CERT) is True
    # unsupported algorithm (DSA)
    with pytest.raises(Exception):
        is_selfsigned(DSA_CERT)


def test_get_key_type_from_certificate():
    from lemur.common.utils import get_key_type_from_certificate
    assert (get_key_type_from_certificate(SAN_CERT_STR) == "RSA2048")
    assert (get_key_type_from_certificate(ECDSA_SECP384r1_CERT_STR) == "ECCSECP384R1")


def test_convert_pkcs7_bytes_to_pem():
    from lemur.common.utils import convert_pkcs7_bytes_to_pem
    from lemur.common.utils import parse_certificate
    cert_chain = convert_pkcs7_bytes_to_pem(CERT_CHAIN_PKCS7_PEM)
    assert (len(cert_chain) == 3)

    leaf = cert_chain[1]
    root = cert_chain[2]

    assert (parse_certificate("\n".join(str(root).splitlines())) == ROOTCA_CERT)
    assert (parse_certificate("\n".join(str(leaf).splitlines())) == INTERMEDIATE_CERT)


def test_encryption(client):
    from lemur.common.utils import data_encrypt, data_decrypt
    plaintext = "encrypt this string"
    assert (data_decrypt(data_encrypt(plaintext)) == plaintext)

    plaintext = 123
    assert (data_decrypt(data_encrypt(plaintext)) == str(plaintext))

    plaintext = {"this": "is a test"}
    assert (data_decrypt(data_encrypt(plaintext)) == str(plaintext))


def test_is_json():
    from lemur.common.utils import is_json
    assert is_json("{}") is True
    assert is_json("{some text}") is False
    assert is_json("{'value':100 }") is False
    assert is_json('{ "value":100}') is True
    assert is_json("{\"value\":100 }") is True
    assert is_json('{"range":[5,6.8],"name":"something"}') is True


def drop_last_cert_from_chain(self):
    from lemur.common.utils import drop_last_cert_from_chain
    chain_pem = drop_last_cert_from_chain(ACME_CHAIN_LONG_STR)
    self.assertEqual(chain_pem, ACME_CHAIN_LONG_STR[len(SAN_CERT_STR + ACME_CHAIN_X1_STR):].lstrip())
