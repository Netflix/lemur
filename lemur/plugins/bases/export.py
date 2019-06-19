"""
.. module: lemur.plugins.bases.export
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class ExportPlugin(Plugin):
    """
    This is the base class from which all supported
    exporters will inherit from.
    """

    type = "export"
    requires_key = True

    def export(self, body, chain, key, options, **kwargs):
        raise NotImplementedError
