"""
.. module: lemur.plugins.bases.source
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin


class SourcePlugin(Plugin):
    type = "source"

    default_options = [
        {
            "name": "pollRate",
            "type": "int",
            "required": False,
            "helpMessage": "Rate in seconds to poll source for new information.",
            "default": "60",
        }
    ]

    def get_certificates(self, options, **kwargs):
        raise NotImplementedError

    def get_endpoints(self, options, **kwargs):
        raise NotImplementedError

    def clean(self, certificate, options, **kwargs):
        raise NotImplementedError

    @property
    def options(self):
        """
        Gets/sets options for the plugin.

        :return:
        """
        return self.default_options + self.additional_options
