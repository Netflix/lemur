"""
.. module: lemur.bases.source
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class SourcePlugin(Plugin):
    type = 'source'

    def get_certificates(self):
        raise NotImplemented

    def get_options(self):
        return {}
