import os
from ast import literal_eval

_basedir = os.path.abspath(os.path.dirname(__file__))

CORS = os.environ.get("CORS") == "True"
debug = os.environ.get("DEBUG") == "True"

SECRET_KEY = repr(os.environ.get('SECRET_KEY','Hrs8kCDNPuT9vtshsSWzlrYW+d+PrAXvg/HwbRE6M3vzSJTTrA/ZEw=='))

LEMUR_TOKEN_SECRET = repr(os.environ.get('LEMUR_TOKEN_SECRET','YVKT6nNHnWRWk28Lra1OPxMvHTqg1ZXvAcO7bkVNSbrEuDQPABM0VQ=='))
LEMUR_ENCRYPTION_KEYS = repr(os.environ.get('LEMUR_ENCRYPTION_KEYS','Ls-qg9j3EMFHyGB_NL0GcQLI6622n9pSyGM_Pu0GdCo='))

LEMUR_WHITELISTED_DOMAINS = []

LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []


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
