"""
.. module: lemur.plugins.utils
    :platform: Unix

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""


def get_plugin_option(name, options):
    """
    Retrieve option name from options dict.
    :param options:
    :return:
    """
    for o in options:
        if o.get('name') == name:
            return o['value']
