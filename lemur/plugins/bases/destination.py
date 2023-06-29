"""
.. module: lemur.plugins.bases.destination
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from lemur.plugins.base import Plugin, plugins


class DestinationPlugin(Plugin):
    type = "destination"
    requires_key = True
    sync_as_source = False
    sync_as_source_name = ""

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        raise NotImplementedError

    def allow_multiple_per_account(self):
        """
        Specifies whether or not multiple of this destination type may be added per AWS account.
        """
        return False


class ExportDestinationPlugin(DestinationPlugin):
    default_options = [
        {
            "name": "exportPlugin",
            "type": "export-plugin",
            "required": True,
            "helpMessage": "Export plugin to use before sending data to destination.",
        }
    ]

    @property
    def options(self):
        """
        Gets/sets options for the plugin.

        :return:
        """
        return self.default_options + self.additional_options

    def export(self, body, private_key, cert_chain, options):
        export_plugin = self.get_option("exportPlugin", options)

        if export_plugin:
            plugin = plugins.get(export_plugin["slug"])
            extension, passphrase, data = plugin.export(
                body, cert_chain, private_key, export_plugin["plugin_options"]
            )
            return [(extension, passphrase, data)]

        data = body + "\n" + cert_chain + "\n" + private_key
        return [(".pem", "", data)]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        raise NotImplementedError
