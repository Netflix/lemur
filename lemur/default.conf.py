# This is just Python which means you can inherit and tweak settings

import os

_basedir = os.path.abspath(os.path.dirname(__file__))

THREADS_PER_PAGE = 8

# General

# These will need to be set to `True` if you are developing locally
CORS = False
DEBUG = False

# Logging

LOG_LEVEL = "DEBUG"
LOG_FILE = "lemur.log"
LOG_REQUEST_HEADERS = False
LOG_SANITIZE_REQUEST_HEADERS = True
LOG_REQUEST_HEADERS_SKIP_ENDPOINT = ["/metrics", "/healthcheck"]
