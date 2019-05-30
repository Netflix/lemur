def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("cfssl-issuer")
    assert p
