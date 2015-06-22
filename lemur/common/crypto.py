"""
.. module: lemur.common.crypto
    :platform: Unix
    :synopsis: This module contains all cryptographic function's in Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import os
import ssl
import StringIO
import functools
from Crypto import Random
from Crypto.Cipher import AES
from hashlib import sha512

from flask import current_app

from lemur.factory import create_app


old_init = ssl.SSLSocket.__init__

@functools.wraps(old_init)
def ssl_bug(self, *args, **kwargs):
  kwargs['ssl_version'] = ssl.PROTOCOL_TLSv1
  old_init(self, *args, **kwargs)

ssl.SSLSocket.__init__ = ssl_bug


def derive_key_and_iv(password, salt, key_length, iv_length):
    """
    Derives the key and iv from the password and salt.

    :param password:
    :param salt:
    :param key_length:
    :param iv_length:
    :return: key, iv
    """
    d = d_i = ''

    while len(d) < key_length + iv_length:
        d_i = sha512(d_i + password + salt).digest()
        d += d_i

    return d[:key_length], d[key_length:key_length+iv_length]


def encrypt(in_file, out_file, password, key_length=32):
    """
    Encrypts a file.

    :param in_file:
    :param out_file:
    :param password:
    :param key_length:
    """
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = bs - (len(chunk) % bs)
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))


def decrypt(in_file, out_file, password, key_length=32):
    """
    Decrypts a file.

    :param in_file:
    :param out_file:
    :param password:
    :param key_length:
    :raise ValueError:
    """
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            if padding_length < 1 or padding_length > bs:
                raise ValueError("bad decrypt pad (%d)" % padding_length)
            # all the pad-bytes must be the same
            if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                # this is similar to the bad decrypt:evp_enc.c from openssl program
                raise ValueError("bad decrypt")
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)


def encrypt_string(string, password):
    """
    Encrypts a string.

    :param string:
    :param password:
    :return:
    """
    in_file = StringIO.StringIO(string)
    enc_file = StringIO.StringIO()
    encrypt(in_file, enc_file, password)
    enc_file.seek(0)
    return enc_file.read()


def decrypt_string(string, password):
    """
    Decrypts a string.

    :param string:
    :param password:
    :return:
    """
    in_file = StringIO.StringIO(string)
    out_file = StringIO.StringIO()
    decrypt(in_file, out_file, password)
    out_file.seek(0)
    return out_file.read()


def lock(password):
    """
    Encrypts Lemur's KEY_PATH. This directory can be used to store secrets needed for normal
    Lemur operation. This is especially useful for storing secrets needed for communication
    with third parties (e.g. external certificate authorities).

    Lemur does not assume anything about the contents of the directory and will attempt to
    encrypt all files contained within. Currently this has only been tested against plain
    text files.

    :param password:
    """
    dest_dir = os.path.join(current_app.config.get("KEY_PATH"), "encrypted")

    if not os.path.exists(dest_dir):
        current_app.logger.debug("Creating encryption directory: {0}".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(os.path.join(current_app.config.get("KEY_PATH"), 'decrypted')):
        for f in files:
            source = os.path.join(root, f)
            dest = os.path.join(dest_dir, f + ".enc")
            with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
                encrypt(in_file, out_file, password)


def unlock(password):
    """
    Decrypts Lemur's KEY_PATH, allowing lemur to use the secrets within.

    This reverses the :func:`lock` function.

    :param password:
    """
    dest_dir = os.path.join(current_app.config.get("KEY_PATH"), "decrypted")
    source_dir = os.path.join(current_app.config.get("KEY_PATH"), "encrypted")

    if not os.path.exists(dest_dir):
        current_app.logger.debug("Creating decryption directory: {0}".format(dest_dir))
        os.makedirs(dest_dir)

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            source = os.path.join(source_dir, f)
            dest = os.path.join(dest_dir, ".".join(f.split(".")[:-1]))
            with open(source, 'rb') as in_file, open(dest, 'wb') as out_file:
                current_app.logger.debug("Writing file: {0} Source: {1}".format(dest, source))
                decrypt(in_file, out_file, password)

