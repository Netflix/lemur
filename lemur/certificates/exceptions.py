"""
.. module: lemur.certificates.exceptions
    :synopsis: Defines all monterey specific exceptions
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app
from lemur.exceptions import LemurException


class UnknownAuthority(LemurException):
    def __init__(self, authority):
        self.code = 404
        self.authority = authority
        self.data = {"message": "The authority specified '{}' is not a valid authority".format(self.authority)}

        current_app.logger.warning(self)

    def __str__(self):
        return repr(self.data['message'])


class InsufficientDomains(LemurException):
    def __init__(self):
        self.code = 400
        self.data = {"message": "Need at least one domain specified in order create a certificate"}

        current_app.logger.warning(self)

    def __str__(self):
        return repr(self.data['message'])


class InvalidCertificate(LemurException):
    def __init__(self):
        self.code = 400
        self.data = {"message": "Need at least one domain specified in order create a certificate"}

        current_app.logger.warning(self)

    def __str__(self):
        return repr(self.data['message'])


class UnableToCreateCSR(LemurException):
    def __init__(self):
        self.code = 500
        self.data = {"message": "Unable to generate CSR"}

        current_app.logger.error(self)

    def __str__(self):
        return repr(self.data['message'])


class UnableToCreatePrivateKey(LemurException):
    def __init__(self):
        self.code = 500
        self.data = {"message": "Unable to generate Private Key"}

        current_app.logger.error(self)

    def __str__(self):
        return repr(self.data['message'])


class MissingFiles(LemurException):
    def __init__(self, path):
        self.code = 500
        self.path = path
        self.data = {"path": self.path, "message": "Expecting missing files"}

        current_app.logger.error(self)

    def __str__(self):
        return repr(self.data['message'])


class NoPersistanceFound(LemurException):
    def __init__(self):
        self.code = 500
        self.data = {"code": 500, "message": "No peristence method found, Lemur cannot persist sensitive information"}

        current_app.logger.error(self)

    def __str__(self):
        return repr(self.data['message'])
