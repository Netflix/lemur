
# This is just Python which means you can inherit and tweak settings

import os
_basedir = os.path.abspath(os.path.dirname(__file__))

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
debug = False

TESTING = True

# this is the secret key used by flask session management
SECRET_KEY = 'I/dVhOZNSMZMqrFJa5tWli6VQccOGudKerq3eWPMSzQNmHHVhMAQfQ=='

# You should consider storing these separately from your config
LEMUR_TOKEN_SECRET = 'test'
LEMUR_ENCRYPTION_KEYS = 'o61sBLNBSGtAckngtNrfVNd8xy8Hp9LBGDstTbMbqCY='

# List of domain regular expressions that non-admin users can issue
LEMUR_WHITELISTED_DOMAINS = [
    r'^[a-zA-Z0-9-]+\.example\.com$',
    r'^[a-zA-Z0-9-]+\.example\.org$',
    r'^example\d+\.long\.com$',
]

# Mail Server

# Lemur currently only supports SES for sending email, this address
# needs to be verified
LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = ['security@example.com']

LEMUR_HOSTNAME = 'lemur.example.com'

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"

LEMUR_DEFAULT_COUNTRY = 'US'
LEMUR_DEFAULT_STATE = 'California'
LEMUR_DEFAULT_LOCATION = 'Los Gatos'
LEMUR_DEFAULT_ORGANIZATION = 'Example, Inc.'
LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = 'Example'

LEMUR_ALLOW_WEEKEND_EXPIRATION = False

# Database

# modify this if you are not using a local database
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://lemur:lemur@localhost:5432/lemur')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# AWS
LEMUR_INSTANCE_PROFILE = 'Lemur'

# Issuers

# These will be dependent on which 3rd party that Lemur is
# configured to use.

# CLOUDCA_URL = ''
# CLOUDCA_PEM_PATH = ''
# CLOUDCA_BUNDLE = ''

# number of years to issue if not specified
# CLOUDCA_DEFAULT_VALIDITY = 2


DIGICERT_URL = 'mock://www.digicert.com'
DIGICERT_ORDER_TYPE = 'ssl_plus'
DIGICERT_API_KEY = 'api-key'
DIGICERT_ORG_ID = 111111
DIGICERT_ROOT = "ROOT"


VERISIGN_URL = 'http://example.com'
VERISIGN_PEM_PATH = '~/'
VERISIGN_FIRST_NAME = 'Jim'
VERISIGN_LAST_NAME = 'Bob'
VERSIGN_EMAIL = 'jim@example.com'


ACME_AWS_ACCOUNT_NUMBER = '11111111111'

ACME_PRIVATE_KEY = '''
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'''

ACME_ROOT = """
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
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
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----
"""
ACME_URL = 'https://acme-v01.api.letsencrypt.org'
ACME_EMAIL = 'jim@example.com'
ACME_TEL = '4088675309'
ACME_DIRECTORY_URL = 'https://acme-v01.api.letsencrypt.org'

LDAP_AUTH = True
LDAP_BIND_URI = 'ldap://localhost'
LDAP_BASE_DN = 'dc=example,dc=com'
LDAP_EMAIL_DOMAIN = 'example.com'
LDAP_REQUIRED_GROUP = 'Lemur Access'
LDAP_DEFAULT_ROLE = 'role1'
