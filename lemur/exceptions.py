"""
.. module: lemur.exceptions
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask import current_app


class LemurException(Exception):
    def __init__(self):
        current_app.logger.error(self)


class AuthenticationFailedException(LemurException):
    def __init__(self, remote_ip, user_agent):
        self.remote_ip = remote_ip
        self.user_agent = user_agent

    def __str__(self):
        return repr("Failed login from: {} {}".format(self.remote_ip, self.user_agent))


class IntegrityError(LemurException):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return repr(self.message)


class InvalidListener(LemurException):
    def __str__(self):
        return repr("Invalid listener, ensure you select a certificate if you are using a secure protocol")


class CertificateUnavailable(LemurException):
    def __str__(self):
        return repr("The certificate requested is not available")


class AttrNotFound(LemurException):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr("The field '{0}' is not sortable".format(self.field))


class NoPersistanceFound(Exception):
    def __str__(self):
        return repr("No peristence method found, Lemur cannot persist sensitive information")


class NoEncryptionKeyFound(Exception):
    def __str__(self):
        return repr("Aborting... Lemur cannot locate db encryption key, is ENCRYPTION_KEY set?")


class InvalidToken(Exception):
    def __str__(self):
        return repr("Invalid token")
