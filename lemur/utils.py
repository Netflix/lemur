"""
.. module: lemur.utils
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app


def get_key():
    """
    Gets the current encryption key

    :return:
    """
    try:
        return current_app.config.get('LEMUR_ENCRYPTION_KEY')
    except RuntimeError:
        return ''
