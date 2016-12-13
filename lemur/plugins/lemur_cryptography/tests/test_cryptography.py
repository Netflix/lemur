import arrow


def test_build_root_certificate():
    from lemur.plugins.lemur_cryptography.plugin import build_root_certificate

    options = {
        'key_type': 'RSA2048',
        'country': 'US',
        'state': 'CA',
        'location': 'Example place',
        'organization': 'Example, Inc.',
        'organizational_unit': 'Example Unit',
        'common_name': 'Example ROOT',
        'validity_start': arrow.get('2016-12-01').datetime,
        'validity_end': arrow.get('2016-12-02').datetime,
        'first_serial': 1

    }
    cert_pem, private_key_pem = build_root_certificate(options)

    assert cert_pem
    assert private_key_pem


def test_issue_certificate(authority):
    from lemur.tests.vectors import CSR_STR
    from lemur.plugins.lemur_cryptography.plugin import issue_certificate

    options = {
        'authority': authority,
        'validity_start': arrow.get('2016-12-01').datetime,
        'validity_end': arrow.get('2016-12-02').datetime
    }
    cert = issue_certificate(CSR_STR, options)
    assert cert
