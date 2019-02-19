"""
.. module: lemur.plugins.lemur_vault.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to hashi vault
     that can be pulled down by end point nodes.

.. moduleauthor:: Christopher Jolley <chris@alwaysjolley.com>
"""
import hvac

#import lemur_vault
from flask import current_app

from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate
from lemur.plugins.bases import DestinationPlugin

class VaultDestinationPlugin(DestinationPlugin):
    """Hashicorp Vault Destination plugin for Lemur"""
    title = 'Vault'
    slug = 'hashi-vault-destination'
    description = 'Allow the uploading of certificates to Hashi Vault as secret'

    author = 'Christopher Jolley'
    author_url = 'https://github.com/alwaysjolley/lemur'

    options = [
        {
            'name': 'vaultMount',
            'type': 'str',
            'required': True,
            'validation': '^[a-zA-Z0-9]+$',
            'helpMessage': 'Must be a valid Vault secrets mount name!'
        },
        {
            'name': 'vaultPath',
            'type': 'str',
            'required': True,
            'validation': '^([a-zA-Z0-9_-]+/?)+$',
            'helpMessage': 'Must be a valid Vault secrets path'
        },
        {
            'name': 'vaultUrl',
            'type': 'str',
            'required': True,
            'validation': '^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?$',
            'helpMessage': 'Must be a valid Vault server url'
        }
    ]

    def __init__(self, *args, **kwargs):
        super(VaultDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """
        cn = common_name(parse_certificate(body))
        data = {}
        #current_app.logger.warning("Cert body content: {0}".format(body))

        token = current_app.config.get('VAULT_TOKEN')

        mount = self.get_option('vaultMount', options)
        path = '{0}/{1}'.format(self.get_option('vaultPath', options),cn)
        url = self.get_option('vaultUrl', options)

        client = hvac.Client(url=url, token=token)

        data['cert'] = cert_chain
        data['key'] = private_key

        ## upload certificate and key
        try:
            client.secrets.kv.v1.create_or_update_secret(path=path, mount_point=mount, secret=data)
        except Exception as err:
            current_app.logger.exception(
                "Exception uploading secret to vault: {0}".format(err), exc_info=True)
