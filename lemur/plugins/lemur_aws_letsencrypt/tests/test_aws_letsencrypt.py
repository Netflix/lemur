from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography import x509
from cryptography.x509 import ExtensionOID, Extension, SubjectAlternativeName, DNSName, IPAddress
from cryptography.hazmat.backends import default_backend
from moto import mock_route53

import boto
import datetime

LETS_ENCRYPT_CERT = b"""
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAOeTkL6SBwNJGF95dYHlyoMwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTIwMDIw
WhcNMjAwNjA0MTIwMDIwWjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AGvM/XGv8yafGRGMPP6hnggoI9DGWGf4l0mzjBhuCkDVqoG/7rsH1ytzteePxiA3
7kqSBo0fXu5GmbWOw09GpwPYyAAY0iWOMU6ybrTJHS466Urzoe/4IwLQoQc219EK
lh+4Ugu1q4KxNY1qMDA/1YX2Qm9M6AcAs1UvZKHSpJQAbsYrbN6obNoUGOeG6ONH
Yr8KRQz5FMfZYcA49fmdDTwKn/pyLOkJFeA/dm/oP99UmKCFoeOa5w9YJr2Vi7ic
Xd59CU8mprWhxFXnma1oU3T8ZNovjib3UHocjlEJfNbDy9zgKTYURcMVweo1dkbH
NbLc5mIjIk/kJ+RPD+chR+gJjy3Gh9xMNkDrZQKfsIO93hxTsZMmgZQ4c+vujC1M
jSak+Ai87YZeYQPh1fCGMSTno5III37DUCtIn8BJxJixuPeOMKsjLLD5AtMVy0fp
d19lcUek4bjDY8/Ujb5/wfn2+Kk7z72SxWdekjtHOWBmKxqq8jDuuMw4ymg1g5n7
R7TZ/Y3y4bTpWUDkBHFo03xNM21wBFDIrCZZeVhvDW4MtT6+Ass2bcpoHwYcGol2
gaLDa5k2dkG41OGtXa0fY+TjdryY4cOcstJUKjv2MJku4yaTtjjECX1rJvFLnqYe
wC+FmxjgWPuyRNuLDAWK30mmpcJZ3CmD6dFtAi4h7H37
-----END CERTIFICATE-----
"""

def test_create_authority(app):
    from lemur.plugins.base import plugins
    p = plugins.get('awsletsencrypt-issuer')
    app.config['LETS_ENCRYPT_ROOT'] = LETS_ENCRYPT_CERT
    root, intermediate, roles = p.create_authority([])
    assert root == LETS_ENCRYPT_CERT
    assert len(roles) == 1
    assert intermediate == ""

def test_get_subject_alternative_hosts(app):
    from lemur.plugins.lemur_aws_letsencrypt.plugin import get_subject_alternative_hosts
    options = {
        "country": "US",
        "state": "CA",
        "location": "A Place",
        "organization": "ExampleInc.",
        "organizationalUnit": "Operations",

        "owner": "mikhail.khodorovskiy@jivesoftware.com",
        "description": "test",
        "authority": {
            'name': 'DoctestCA'
        },
        "extensions": {
            "subAltNames": {
                "names": [{
                    'nameType': 'DNSName',
                    'value': u'test-aws-lets-encrypt.dev.miru.io'
                }, {
                    'nameType': 'IPAddress',
                    'value': u'127.0.0.1'
                }]
            }
        },
        "commonName": "test-aws-lets-encrypt.miru.io",
        "validityStart": "2015-06-05T07:00:00.000Z",
        "validityEnd": "2015-06-16T07:00:00.000Z",
    }
    hosts = get_subject_alternative_hosts(options)
    assert len(hosts) == 1
    assert hosts[0] == u'test-aws-lets-encrypt.dev.miru.io'


@mock_route53()
def test_find_zone_id():
    conn = boto.connect_route53('key', 'secret')
    zone = conn.create_hosted_zone("test.com")
    zoneid = zone["CreateHostedZoneResponse"]["HostedZone"]["Id"].split("/")[-1]
    assert len(zoneid) > 0
    from lemur.plugins.lemur_aws_letsencrypt.plugin import find_zone_id_for_domain
    assert zoneid == find_zone_id_for_domain(conn, 'test.com')

@mock_route53()
def test_change_txt_record():
    conn = boto.connect_route53('key', 'secret')
    zone = conn.create_hosted_zone("test.com")
    zoneid = zone["CreateHostedZoneResponse"]["HostedZone"]["Id"].split("/")[-1]
    assert len(zoneid) > 0
    from lemur.plugins.lemur_aws_letsencrypt.plugin import change_txt_record

    change_info = change_txt_record(conn, 'CREATE', zoneid, 'test.com', 'test')

    assert change_info

    rrsets = conn.get_all_rrsets(zoneid, type="TXT")
    assert len(rrsets) == 1
    assert rrsets[0].resource_records[0] == '"test"'


'''
def test_create_certificate(app):
    from lemur.plugins.base import plugins
    p = plugins.get('awsletsencrypt-issuer')
    app.config['LETS_ENCRYPT_DEFAULT_DIRECTORY'] = 'https://acme-staging.api.letsencrypt.org/directory'
    app.config['LETS_ENCRYPT_ROOT'] = LETS_ENCRYPT_CERT

    options = {
        "country": "US",
        "state": "CA",
        "location": "A Place",
        "organization": "ExampleInc.",
        "organizationalUnit": "Operations",

        "owner": "mikhail.khodorovskiy@jivesoftware.com",
        "description": "test",
        "authority": {
            'name': 'DoctestCA'
        },
        "extensions": {
            "subAltNames": {
                "names": [{
                    'nameType': 'DNSName',
                    'value': u'test-aws-lets-encrypt.test.bikou-labs.net'
                }, {
                    'nameType': 'IPAddress',
                    'value': u'127.0.0.1'
                }]
            }
        },
        "commonName": "test-aws-lets-encrypt.bikou-labs.net",
        "validityStart": "2015-06-05T07:00:00.000Z",
        "validityEnd": "2015-06-16T07:00:00.000Z",
    }

    common_name = x509.NameAttribute(x509.OID_COMMON_NAME, unicode(options['commonName']))
    subject = x509.Name([common_name,
                         x509.NameAttribute(x509.OID_ORGANIZATION_NAME, unicode(options['organization'])),
                         x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, unicode(options['organizationalUnit'])),
                         x509.NameAttribute(x509.OID_COUNTRY_NAME, unicode(options['country'])),
                         x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, unicode(options['state'])),
                         x509.NameAttribute(x509.OID_LOCALITY_NAME, unicode(options['location'])), ])


    root, intermediate, roles = p.create_authority([])

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    csr = request.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    cert, chain = p.create_certificate(csr, options)

    app.logger.debug('cert: ' + cert)

    assert len(roles) == 1
    assert intermediate == ""
    cert = x509.load_pem_x509_certificate(str(cert), default_backend())

    now = datetime.datetime.now()
    three_month_from_now = datetime.datetime(now.year, now.month + 3, now.day, now.hour, now.minute)

    assert cert.not_valid_before > datetime.datetime(now.year, now.month, now.day - 1, now.hour, now.minute)
    assert cert.not_valid_after < three_month_from_now

    assert isinstance(cert.public_key(), RSAPublicKey)
    assert cert.issuer == x509.load_pem_x509_certificate(str(chain), default_backend()).subject

    assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0] == common_name
    assert cert.signature_hash_algorithm.name == 'sha256'
    assert cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME) == Extension(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=False, value=SubjectAlternativeName([
            DNSName(u'test-aws-lets-encrypt.bikou-labs.net')
        ]))
'''

