"""
.. module: authority
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from flask import current_app


class Issuer(object):
    """
    This is the base class from which all of the supported
    issuers will inherit from.
    """

    def __init__(self):
        self.dry_run = current_app.config.get('DRY_RUN')

    def create_certificate(self):
        raise NotImplementedError

    def create_authority(self):
        raise NotImplementedError

    def get_authorities(self):
        raise NotImplementedError

