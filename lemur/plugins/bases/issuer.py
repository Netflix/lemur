"""
.. module: lemur.plugins.bases.issuer
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class IssuerPlugin(Plugin):
    """
    This is the base class from which all of the supported
    issuers will inherit from.
    """
    type = 'issuer'

    def create_certificate(self, csr, issuer_options):
        raise NotImplementedError

    def create_authority(self, options):
        raise NotImplementedError
