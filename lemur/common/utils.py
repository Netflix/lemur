"""
.. module: lemur.common.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import string
import random

import sqlalchemy
from sqlalchemy import and_, func

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


# https://bitbucket.org/zzzeek/sqlalchemy/wiki/UsageRecipes/WindowedRangeQuery
def column_windows(session, column, windowsize):
    """Return a series of WHERE clauses against
    a given column that break it into windows.

    Result is an iterable of tuples, consisting of
    ((start, end), whereclause), where (start, end) are the ids.

    Requires a database that supports window functions,
    i.e. Postgresql, SQL Server, Oracle.

    Enhance this yourself !  Add a "where" argument
    so that windows of just a subset of rows can
    be computed.

    """
    def int_for_range(start_id, end_id):
        if end_id:
            return and_(
                column >= start_id,
                column < end_id
            )
        else:
            return column >= start_id

    q = session.query(
        column,
        func.row_number().over(order_by=column).label('rownum')
    ).from_self(column)

    if windowsize > 1:
        q = q.filter(sqlalchemy.text("rownum %% %d=1" % windowsize))

    intervals = [id for id, in q]

    while intervals:
        start = intervals.pop(0)
        if intervals:
            end = intervals[0]
        else:
            end = None
        yield int_for_range(start, end)


def windowed_query(q, column, windowsize):
    """"Break a Query into windows on a given column."""

    for whereclause in column_windows(
            q.session,
            column, windowsize):
        for row in q.filter(whereclause).order_by(column):
            yield row
