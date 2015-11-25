"""
.. module: lemur.bases.export
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class ExportPlugin(Plugin):
    type = 'export'

    def export(self):
        raise NotImplemented
