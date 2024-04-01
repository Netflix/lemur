import json
import os
import uuid

import google.cloud.security.privateca_v1 as private_ca
from flask import current_app
from google.protobuf import duration_pb2

from lemur.exceptions import InvalidConfiguration
from lemur.plugins import lemur_google_ca as gca, VERSION
from lemur.plugins.bases import IssuerPlugin


class GoogleCaIssuerPlugin(IssuerPlugin):
    title = "Google CA"
    slug = "googleca-issuer"
    description = "Enables the creation of certificates by Google CA"
    version = gca.VERSION

    author = "Oleg Dopertchouk"
    author_url = "https://github.com/sqsp"

    options = [
        {
            "name": "CAPool",
            "type": "str",
            "required": True,
            "value": "ca-pool1",
            "validation": "(?i)^[a-zA-Z_0-9.-]+$",
            "helpMessage": "Must be a valid GCP name!",
        },
        {
            "name": "Duration",
            "type": "int",
            "required": False,
            "value": 365,
            "validation": "(?i)[0-9]+$",
            "helpMessage": "Duration in days",
        },
    ]