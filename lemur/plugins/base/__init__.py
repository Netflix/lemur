"""
.. module: lemur.plugins.base
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from lemur.plugins.base.manager import PluginManager
from lemur.plugins.base.v1 import *  # noqa

plugins = PluginManager()
register = plugins.register
unregister = plugins.unregister
