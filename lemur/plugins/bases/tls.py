"""
.. module: lemur.plugins.bases.tls
    :platform: Unix
    :copyright: (c) 2021 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Sayali Charhate <scharhate@netflix.com>
"""
from lemur.plugins.base import Plugin


class TLSPlugin(Plugin):
    """
    This is the base class from which all supported
    tls session providers will inherit from.
    """
    type = "tls"

    def session(self, server_application):
        raise NotImplementedError
