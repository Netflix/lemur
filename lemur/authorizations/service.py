"""
.. module: lemur.pending_certificates.service
    Copyright (c) 2018 and onwards Netflix, Inc.  All rights reserved.
.. moduleauthor:: Secops <secops@netflix.com>
"""
from lemur import database

from lemur.authorizations.models import Authorization


def get(authorization_id):
    """
    Retrieve dns authorization by ID
    """
    return database.get(Authorization, authorization_id)


def create(account_number, domains, dns_provider_type, options=None):
    """
    Creates a new dns authorization.
    """

    authorization = Authorization(account_number, domains, dns_provider_type, options)
    return database.create(authorization)
