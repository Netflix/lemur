import pytest
from jks import KeyStore, TrustedCertEntry, PrivateKeyEntry

from lemur.tests.vectors import (
    INTERNAL_CERTIFICATE_A_STR,
    SAN_CERT_STR,
    INTERMEDIATE_CERT_STR,
    ROOTCA_CERT_STR,
    SAN_CERT_KEY,
)


def test_export_truststore(app):
    from lemur.plugins.base import plugins

    p = plugins.get("java-truststore-jks")
    options = [
        {"name": "passphrase", "value": "hunter2"},
        {"name": "alias", "value": "AzureDiamond"},
    ]
    chain = INTERMEDIATE_CERT_STR + "\n" + ROOTCA_CERT_STR
    ext, password, raw = p.export(SAN_CERT_STR, chain, SAN_CERT_KEY, options)

    assert ext == "jks"
    assert password == "hunter2"
    assert isinstance(raw, bytes)

    ks = KeyStore.loads(raw, "hunter2")
    assert ks.store_type == "jks"
    # JKS lower-cases alias strings
    assert ks.entries.keys() == {
        "azurediamond_cert",
        "azurediamond_cert_1",
        "azurediamond_cert_2",
    }
    assert isinstance(ks.entries["azurediamond_cert"], TrustedCertEntry)


def test_export_truststore_defaults(app):
    from lemur.plugins.base import plugins

    p = plugins.get("java-truststore-jks")
    options = []
    ext, password, raw = p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    assert ext == "jks"
    assert isinstance(password, str)
    assert isinstance(raw, bytes)

    ks = KeyStore.loads(raw, password)
    assert ks.store_type == "jks"
    # JKS lower-cases alias strings
    assert ks.entries.keys() == {"acommonname_cert"}
    assert isinstance(ks.entries["acommonname_cert"], TrustedCertEntry)


def test_export_keystore(app):
    from lemur.plugins.base import plugins

    p = plugins.get("java-keystore-jks")
    options = [
        {"name": "passphrase", "value": "hunter2"},
        {"name": "alias", "value": "AzureDiamond"},
    ]

    chain = INTERMEDIATE_CERT_STR + "\n" + ROOTCA_CERT_STR
    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, chain, "", options)

    ext, password, raw = p.export(SAN_CERT_STR, chain, SAN_CERT_KEY, options)

    assert ext == "jks"
    assert password == "hunter2"
    assert isinstance(raw, bytes)

    ks = KeyStore.loads(raw, password)
    assert ks.store_type == "jks"
    # JKS lower-cases alias strings
    assert ks.entries.keys() == {"azurediamond"}
    entry = ks.entries["azurediamond"]
    assert isinstance(entry, PrivateKeyEntry)
    assert len(entry.cert_chain) == 3  # Cert and chain were provided


def test_export_keystore_defaults(app):
    from lemur.plugins.base import plugins

    p = plugins.get("java-keystore-jks")
    options = []

    with pytest.raises(Exception):
        p.export(INTERNAL_CERTIFICATE_A_STR, "", "", options)

    ext, password, raw = p.export(SAN_CERT_STR, "", SAN_CERT_KEY, options)

    assert ext == "jks"
    assert isinstance(password, str)
    assert isinstance(raw, bytes)

    ks = KeyStore.loads(raw, password)
    assert ks.store_type == "jks"
    assert ks.entries.keys() == {"san.example.org"}
    entry = ks.entries["san.example.org"]
    assert isinstance(entry, PrivateKeyEntry)
    assert len(entry.cert_chain) == 1  # Only cert itself, no chain was provided
