"""
.. module: lemur.common.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import sys
import string
import random

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from flask.ext.restful.reqparse import RequestParser

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
    if sys.version_info >= (3, 0):
        if isinstance(body, bytes):
            return x509.load_pem_x509_certificate(body, default_backend())
        return x509.load_pem_x509_certificate(bytes(body, 'utf8'), default_backend())
    return x509.load_pem_x509_certificate(body.encode('utf-8'), default_backend())


def is_weekend(date):
    """
    Determines if a given date is on a weekend.

    :param date:
    :return:
    """
    if date.weekday() > 5:
        return True
