"""
.. module: lemur.plugins.bases.authorization
    :platform: Unix
    :copyright: (c) 2021 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Sayali Charhate <scharhate@netflix.com>
"""

from lemur.exceptions import LemurException
from lemur.plugins.base import Plugin


class AuthorizationPlugin(Plugin):
    """
    This is the base class for authorization providers. Check if the caller is authorized to access a resource.
    """
    type = "authorization"

    def warmup(self):
        pass

    def is_authorized(self, resource, caller):
        raise NotImplementedError


class DomainAuthorizationPlugin(AuthorizationPlugin):
    """
    This is the base class for domain authorization providers. Check if the caller can issue certificates for a domain.
    """
    type = "domain-authorization"

    def is_authorized(self, domain, caller):
        raise NotImplementedError


class UnauthorizedError(LemurException):
    """
    Raised when user is unauthorized to perform an action on the resource
    """
    def __init__(self, user, resource, action, details="no additional details"):
        self.user = user
        self.resource = resource
        self.action = action
        self.details = details

    def __str__(self):
        return repr(f"{self.user} is not authorized to perform {self.action} on {self.resource}: {self.details}")
