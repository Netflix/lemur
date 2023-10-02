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

# Set of controls to use around ingesting user group information from the IDP
# Allows mapping user groups to Lemur roles and automatically creating them
IDP_GROUPS_KEYS = ["googleGroups"]  # a list of keys used by IDP(s) to return user groups (profile[IDP_GROUPS_KEY])
IDP_ASSIGN_ROLES_FROM_USER_GROUPS = True  # Assigns a Lemur role for each group found attached to the user
IDP_CREATE_ROLES_FROM_USER_GROUPS = True  # Creates a Lemur role for each group found attached to the user if missing
# Protects the built-in groups and prevents dynamically assigning users to them. Prevents IDP admin from becoming
# Lemur admin. Use IDP_ROLES_MAPPING to create a mapping to assign these groups if desired. eg {"admin": "admin"}
IDP_PROTECT_BUILTINS = True
IDP_CREATE_PER_USER_ROLE = True  # Generates Lemur role for each user (allows cert assignment to a single user)
