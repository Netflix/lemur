import os
import random
import string
import base64
from ast import literal_eval

_basedir = os.path.abspath(os.path.dirname(__file__))

CORS = os.environ.get("CORS") == "True"
debug = os.environ.get("DEBUG") == "True"


def get_random_secret(length):
    secret_key = ''.join(random.choice(string.ascii_uppercase) for x in range(round(length / 4)))
    secret_key = secret_key + ''.join(random.choice("~!@#$%^&*()_+") for x in range(round(length / 4)))
    secret_key = secret_key + ''.join(random.choice(string.ascii_lowercase) for x in range(round(length / 4)))
    return secret_key + ''.join(random.choice(string.digits) for x in range(round(length / 4)))


SECRET_KEY = repr(os.environ.get('SECRET_KEY', get_random_secret(32).encode('utf8')))

LEMUR_TOKEN_SECRET = repr(os.environ.get('LEMUR_TOKEN_SECRET',
                                         base64.b64encode(get_random_secret(32).encode('utf8'))))
LEMUR_ENCRYPTION_KEYS = repr(os.environ.get('LEMUR_ENCRYPTION_KEYS',
                                            base64.b64encode(get_random_secret(32).encode('utf8'))))

LEMUR_WHITELISTED_DOMAINS = []

LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []

ALLOW_CERT_DELETION = os.environ.get('ALLOW_CERT_DELETION') == "True"

LEMUR_DEFAULT_COUNTRY = str(os.environ.get('LEMUR_DEFAULT_COUNTRY',''))
LEMUR_DEFAULT_STATE = str(os.environ.get('LEMUR_DEFAULT_STATE',''))
LEMUR_DEFAULT_LOCATION = str(os.environ.get('LEMUR_DEFAULT_LOCATION',''))
LEMUR_DEFAULT_ORGANIZATION = str(os.environ.get('LEMUR_DEFAULT_ORGANIZATION',''))
LEMUR_DEFAULT_ORGANIZATIONAL_UNIT = str(os.environ.get('LEMUR_DEFAULT_ORGANIZATIONAL_UNIT',''))

LEMUR_DEFAULT_ISSUER_PLUGIN = str(os.environ.get('LEMUR_DEFAULT_ISSUER_PLUGIN',''))
LEMUR_DEFAULT_AUTHORITY = str(os.environ.get('LEMUR_DEFAULT_AUTHORITY',''))

ACTIVE_PROVIDERS = []

METRIC_PROVIDERS = []

LOG_LEVEL = str(os.environ.get('LOG_LEVEL','DEBUG'))
LOG_FILE = str(os.environ.get('LOG_FILE','/home/lemur/.lemur/lemur.log'))

SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI','postgresql://lemur:lemur@localhost:5432/lemur')

LDAP_DEBUG = os.environ.get('LDAP_DEBUG') == "True"
LDAP_AUTH = os.environ.get('LDAP_AUTH') == "True"
LDAP_IS_ACTIVE_DIRECTORY = os.environ.get('LDAP_IS_ACTIVE_DIRECTORY') == "True"
LDAP_BIND_URI = str(os.environ.get('LDAP_BIND_URI',''))
LDAP_BASE_DN = str(os.environ.get('LDAP_BASE_DN',''))
LDAP_EMAIL_DOMAIN = str(os.environ.get('LDAP_EMAIL_DOMAIN',''))
LDAP_USE_TLS = str(os.environ.get('LDAP_USE_TLS',''))
LDAP_REQUIRED_GROUP = str(os.environ.get('LDAP_REQUIRED_GROUP',''))
LDAP_GROUPS_TO_ROLES = literal_eval(os.environ.get('LDAP_GROUPS_TO_ROLES') or "{}")
