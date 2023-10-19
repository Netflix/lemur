"""
.. module: lemur.exceptions
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
from flask import current_app


class LemurException(Exception):
    def __init__(self, *args, **kwargs):
        current_app.logger.exception(self)


class DuplicateError(LemurException):
    def __init__(self, key):
        self.key = key

    def __str__(self):
        return repr(f"Duplicate found! Could not create: {self.key}")


class InvalidListener(LemurException):
    def __str__(self):
        return repr(
            "Invalid listener, ensure you select a certificate if you are using a secure protocol"
        )


class InvalidDistribution(LemurException):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr(
            f"Invalid distribution {self.field}, must use IAM certificates"
        )


class TokenExchangeFailed(LemurException):
    def __init__(self, error, description):
        self.error = error
        self.description = description

    def __str__(self):
        return f'Token exchange failed with {self.error}. {self.description}'


class AttrNotFound(LemurException):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr(f"The field '{self.field}' is not sortable or filterable")


class InvalidConfiguration(Exception):
    pass


class InvalidAuthority(Exception):
    pass


class UnknownProvider(Exception):
    pass
