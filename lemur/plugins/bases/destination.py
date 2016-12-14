"""
.. module: lemur.plugins.bases.destination
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class DestinationPlugin(Plugin):
    type = 'destination'
    requires_key = True

    def upload(self):
        raise NotImplemented
