"""
.. module: lemur.common.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import string
import random

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from flask_restful.reqparse import RequestParser

from lemur.exceptions import InvalidConfiguration

paginated_parser = RequestParser()

paginated_parser.add_argument('count', type=int, default=10, location='args')
paginated_parser.add_argument('page', type=int, default=1, location='args')
paginated_parser.add_argument('sortDir', type=str, dest='sort_dir', location='args')
paginated_parser.add_argument('sortBy', type=str, dest='sort_by', location='args')
paginated_parser.add_argument('filter', type=str, location='args')


def get_psuedo_random_string():
    """
    Create a random and strongish challenge.
    """
    challenge = ''.join(random.choice(string.ascii_uppercase) for x in range(6))  # noqa
    challenge += ''.join(random.choice("~!@#$%^&*()_+") for x in range(6))  # noqa
    challenge += ''.join(random.choice(string.ascii_lowercase) for x in range(6))
    challenge += ''.join(random.choice(string.digits) for x in range(6))  # noqa
    return challenge


def parse_certificate(body):
    """
    Helper function that parses a PEM certificate.

    :param body:
    :return:
    """
    if isinstance(body, str):
        body = body.encode('utf-8')

    return x509.load_pem_x509_certificate(body, default_backend())


def generate_private_key(key_type):
    """
    Generates a new private key based on key_type.

    Valid key types: RSA2048, RSA4096

    :param key_type:
    :return:
    """
    valid_key_types = ['RSA2048', 'RSA4096']

    if key_type not in valid_key_types:
        raise Exception("Invalid key type: {key_type}. Supported key types: {choices}".format(
            key_type=key_type,
            choices=",".join(valid_key_types)
        ))

    if 'RSA' in key_type:
        key_size = int(key_type[3:])
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )


def is_weekend(date):
    """
    Determines if a given date is on a weekend.

    :param date:
    :return:
    """
    if date.weekday() > 5:
        return True


def validate_conf(app, required_vars):
    """
    Ensures that the given fields are set in the applications conf.

    :param app:
    :param required_vars: list
    """
    for var in required_vars:
        if not app.config.get(var):
            raise InvalidConfiguration("Required variable '{var}' is not set in Lemur's conf.".format(var=var))
