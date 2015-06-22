"""
.. module: lemur.common.services.issuers.manager
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson (kglisson@netflix.com)
"""
import pkgutil
from importlib import import_module

from flask import current_app

from lemur.common.services.issuers import plugins

# TODO make the plugin dir configurable
def get_plugin_by_name(plugin_name):
    """
    Fetches a given plugin by it's name. We use a known location for issuer plugins and attempt
    to load it such that it can be used for issuing certificates.

    :param plugin_name:
    :return: a plugin `class` :raise Exception: Generic error whenever the plugin specified can not be found.
    """
    for importer, modname, ispkg in pkgutil.iter_modules(plugins.__path__):
        try:
            issuer = import_module('lemur.common.services.issuers.plugins.{0}.{0}'.format(modname))
            if issuer.__name__ == plugin_name:
                # we shouldn't return bad issuers
                issuer_obj = issuer.init()
                return issuer_obj
        except Exception as e:
            current_app.logger.warn("Issuer {0} was unable to be imported: {1}".format(modname, e))

    else:
        raise Exception("Could not find the specified plugin: {0}".format(plugin_name))


