
# This is just Python which means you can inherit and tweak settings

import os
_basedir = os.path.abspath(os.path.dirname(__file__))

ADMINS = frozenset([''])

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

# this is a list of domains as regexes that only admins can issue
LEMUR_RESTRICTED_DOMAINS = []

# Mail Server

# Lemur currently only supports SES for sending email, this address
# needs to be verified
LEMUR_EMAIL = ''
LEMUR_SECURITY_TEAM_EMAIL = []

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"


# Database

# modify this if you are not using a local database
SQLALCHEMY_DATABASE_URI = 'postgresql://lemur:lemur@localhost:5432/lemur'


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

VERISIGN_URL = 'http://example.com'
VERISIGN_PEM_PATH = '~/'
VERISIGN_FIRST_NAME = 'Jim'
VERISIGN_LAST_NAME = 'Bob'
VERSIGN_EMAIL = 'jim@example.com'
