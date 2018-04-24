"""
.. module: lemur.pending_certificates.service
    Copyright (c) 2017 and onwards Instart Logic, Inc.  All rights reserved.
.. moduleauthor:: Secops <secops@netflix.com>
"""
from lemur import database

from lemur.authorizations.models import Authorizations


def get(authorization_id):
    """
    Retrieve dns authorization by ID
    """
    return database.get(Authorizations, authorization_id)


def create(account_number, domains, dns_provider_type, options=None):
    """
    Creates a new dns authorization.
    """

    authorization = Authorizations(account_number, domains, dns_provider_type, options)
    return database.create(authorization)
