#!/usr/bin/python
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins.lemur_linuxdst import remote_host
# It is required that you setup certificate based authentication for the destiation host


class LinuxDstPlugin(DestinationPlugin):

    title = 'Linux Destination Plugin'
    slug = 'linux-destination'
    description = 'Allow the distribution of certificates to a Linux host'
    version = 1

    author = 'Rick Breidenstein '
    author_url = 'https://github.com/RickB17/'

    options = [
        {
            'name': 'dstHost',
            'type': 'str',
            'required': True,
            'helpMessage': 'This is the host you will be sending the certificate to',
        },
        {
            'name': 'dstPort',
            'type': 'int',
            'required': True,
            'helpMessage': 'This is the port SSHD is running on',
            'default': '22'
        },
        {
            'name': 'dstUser',
            'type': 'str',
            'required': True,
            'helpMessage': 'The user name to use on the remote host. Hopefully not root.',
            'default': 'root',
        },
        {
            'name': 'dstPriv',
            'type': 'str',
            'required': True,
            'helpMessage': 'The private key to use for auth',
            'default': '/root/.shh/id_rsa',
        },
        {
            'name': 'dstPrivKey',
            'type': 'str',
            'required': False,
            'helpMessage': 'The password for the destination private key',
            'default': 'somethingsecret',
        },
        {
            'name': 'dstDir',
            'type': 'str',
            'required': True,
            'helpMessage': 'This is the directory on the host you want to send the certificate to',
            'default': '/etc/nginx/certs/'
        },
        {
            "available": [
                "NGINX",
                "3File"
            ],
            "name": "exportType",
            "required": True,
            "value": "NGINX",
            "helpMessage": "Reference the docs for an explaination of each export type",
            "type": "select"
        }
    ]
    requires_key = False

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        export_type = self.get_option('exportType', options)
        dst_host = self.get_option('dstHost', options)
        dst_host_port = self.get_option('dstPort', options)
        dst_user = self.get_option('dstUser', options)
        dst_priv = self.get_option('dstPriv', options)
        dst_priv_key = self.get_option('dstPrivKey', options)
        if len(dst_priv_key):
            dst_priv_key = None
        dst_dir = self.get_option('dstDir', options)
        remote_host.create_cert(name, dst_dir, export_type, dst_user, dst_priv, dst_priv_key, dst_host, int(dst_host_port))
