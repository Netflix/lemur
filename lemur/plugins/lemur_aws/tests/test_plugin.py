def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("aws-s3")
    assert p
