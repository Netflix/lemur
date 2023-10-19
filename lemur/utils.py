"""
.. module: lemur.utils
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import os
import tempfile
from contextlib import contextmanager

import cryptography.fernet
from sqlalchemy import types
from cryptography.fernet import Fernet, MultiFernet
from flask import current_app


@contextmanager
def mktempfile():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        name = f.name

    try:
        yield name
    finally:
        try:
            os.unlink(name)
        except OSError as e:
            current_app.logger.debug(f"No file {name}")


@contextmanager
def mktemppath():
    try:
        path = os.path.join(
            tempfile._get_default_tempdir(), next(tempfile._get_candidate_names())
        )
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError as e:
            current_app.logger.debug(f"No file {path}")


def get_keys():
    """
    Gets the encryption keys.

    This supports multiple keys to facilitate key rotation. The first
    key in the list is used to encrypt. Decryption is attempted with
    each key in succession.

    :return:
    """

    # when running lemur create_config, this code needs to work despite
    # the fact that there is not a current_app with a config at that point
    keys = current_app.config.get("LEMUR_ENCRYPTION_KEYS", [])

    # this function is expected to return a list of keys, but we want
    # to let people just specify a single key
    if not isinstance(keys, list):
        keys = [keys]

    # make sure there is no accidental whitespace
    keys = [key.strip() for key in keys]

    return keys


class Vault(types.TypeDecorator):
    """
    A custom SQLAlchemy column type that transparently handles encryption.

    This uses the MultiFernet from the cryptography package to facilitate
    key rotation. That class handles encryption and signing.

    Fernet uses AES in CBC mode with 128-bit keys and PKCS7 padding. It
    uses HMAC-SHA256 for ciphertext authentication. Initialization
    vectors are generated using os.urandom().
    """

    # required by SQLAlchemy. defines the underlying column type
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        """
        Encrypt values on the way into the database.

        MultiFernet.encrypt uses the first key in the list.
        """

        # we assume that the user's keys are already Fernet keys (32 byte
        # keys that have been base64 encoded).
        self.keys = [Fernet(key) for key in get_keys()]

        if not value:
            return

        # ensure bytes for fernet
        if isinstance(value, str):
            value = value.encode("utf-8")

        return MultiFernet(self.keys).encrypt(value)

    def process_result_value(self, value, dialect):
        """
        Decrypt values on the way out of the database.

        MultiFernet tries each key until one works.
        """

        # we assume that the user's keys are already Fernet keys (32 byte
        # keys that have been base64 encoded).
        self.keys = [Fernet(key) for key in get_keys()]

        # if the value is not a string we aren't going to try to decrypt
        # it. this is for the case where the column is null
        if not value:
            return

        try:
            return MultiFernet(self.keys).decrypt(value).decode("utf8")
        except cryptography.fernet.InvalidToken as e:
            if current_app.config.get("DEBUG", False):
                current_app.logger.error(f"Error decrypting token: {value}")
            else:
                current_app.logger.error("Error decrypting token.  (Enable debugging mode to log the token.)")
            raise
