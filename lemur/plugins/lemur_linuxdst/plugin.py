#!/usr/bin/python
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins import lemur_linuxdst as linuxdst
from lemur.plugins.lemur_linuxdst import remote_host
import os
# It is required that you setup certificate based authentication for the destiation host


class LinuxDstPlugin(DestinationPlugin):

    title = 'Linux Destination Plugin'
    slug = 'linux-destination'
    description = 'Allow the uploading of certificates to a Linux host'
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
            'name': 'dstUser',
            'type': 'str',
            'required': True,
            'helpMessage': 'The user name to use ont he remote host',
            'default': 'root',
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
        # request.post('a third party')
        tempFolder = '/www/lemur-dev/lemur/plugins/lemur_linuxdst/temp'
        exportType = self.get_option('exportType', options)
        certInfo = remote_host.createCert(name, tempFolder, exportType)
        dstUser = self.get_option('dstUser', options)
        dstHost = self.get_option('dstHost', options)
        dstDir = self.get_option('dstDir', options)
        remote_host.copyCert(dstUser, dstHost, dstDir, certInfo['certDir'], options)
