def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("cfssl-issuer")
    assert p


def test_create_authority(app):
    from lemur.plugins.base import plugins

    options = {"name": "test CFSSL authority"}
    p = plugins.get("cfssl-issuer")
    cfssl_root, intermediate, role = p.create_authority(options)
    assert role == [
        {"username": "", "password": "", "name": "cfssl_test_CFSSL_authority_admin"}
    ]
