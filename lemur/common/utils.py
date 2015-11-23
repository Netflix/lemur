"""
.. module: lemur.common.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import string
import random
from functools import wraps

from flask import current_app

from flask.ext.restful import marshal
from flask.ext.restful.reqparse import RequestParser
from flask.ext.sqlalchemy import Pagination


def get_psuedo_random_string():
    """
    Create a random and strongish challenge.
    """
    challenge = ''.join(random.choice(string.ascii_uppercase) for x in range(6))  # noqa
    challenge += ''.join(random.choice("~!@#$%^&*()_+") for x in range(6))  # noqa
    challenge += ''.join(random.choice(string.ascii_lowercase) for x in range(6))
    challenge += ''.join(random.choice(string.digits) for x in range(6))  # noqa
    return challenge


class marshal_items(object):
    def __init__(self, fields, envelope=None):
        self.fields = fields
        self.envelop = envelope

    def __call__(self, f):
        def _filter_items(items):
            filtered_items = []
            for item in items:
                filtered_items.append(marshal(item, self.fields))
            return filtered_items

        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                resp = f(*args, **kwargs)

                # this is a bit weird way to handle non standard error codes returned from the marshaled function
                if isinstance(resp, tuple):
                    return resp[0], resp[1]

                if isinstance(resp, Pagination):
                    return {'items': _filter_items(resp.items), 'total': resp.total}

                if isinstance(resp, list):
                    return {'items': _filter_items(resp), 'total': len(resp)}

                return marshal(resp, self.fields)
            except Exception as e:
                current_app.logger.exception(e)
                # this is a little weird hack to respect flask restful parsing errors on marshaled functions
                if hasattr(e, 'code'):
                    if hasattr(e, 'data'):
                        return {'message': e.data['message']}, 400
                    else:
                        return {'message': {'exception': 'unknown'}}, 400
                else:
                    return {'message': {'exception': str(e)}}, 400
        return wrapper


paginated_parser = RequestParser()

paginated_parser.add_argument('count', type=int, default=10, location='args')
paginated_parser.add_argument('page', type=int, default=1, location='args')
paginated_parser.add_argument('sortDir', type=str, dest='sort_dir', location='args')
paginated_parser.add_argument('sortBy', type=str, dest='sort_by', location='args')
paginated_parser.add_argument('filter', type=str, location='args')
