def test_get_certificates(app):
    from lemur.plugins.base import plugins

    p = plugins.get("verisign-issuer")


def test_create_cis_authority(app):
    from lemur.plugins.lemur_verisign.plugin import VerisignIssuerPlugin

    options = {"name": "test Verisign authority"}
    digicert_root, intermediate, role = VerisignIssuerPlugin.create_authority(options)
    assert role == [
        {
            "username": "",
            "password": "",
            "name": "verisign_test_Verisign_authority_admin",
        }
    ]
