"""
.. module: lemur.plugins.lemur_sftp.plugin
    :platform: Unix
    :synopsis: Allow the uploading of certificates to SFTP.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

    Allow the uploading of certificates to SFTP.

    NGINX and Apache export formats are supported.

    Password and RSA private key are supported.
    Passwords are not encrypted and stored as a plain text.

    Detailed logging when Lemur debug mode is enabled.

.. moduleauthor:: Dmitry Zykov https://github.com/DmitryZykov
"""

import paramiko

from flask import current_app
from lemur.plugins import lemur_sftp
from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate
from lemur.plugins.bases import DestinationPlugin


class SFTPDestinationPlugin(DestinationPlugin):
    title = "SFTP"
    slug = "sftp-destination"
    description = "Allow the uploading of certificates to SFTP"
    version = lemur_sftp.VERSION

    author = "Dmitry Zykov"
    author_url = "https://github.com/DmitryZykov"

    options = [
        {
            "name": "host",
            "type": "str",
            "required": True,
            "helpMessage": "The SFTP host.",
        },
        {
            "name": "port",
            "type": "int",
            "required": True,
            "helpMessage": "The SFTP port, default is 22.",
            "validation": "^(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3})",
            "default": "22",
        },
        {
            "name": "user",
            "type": "str",
            "required": True,
            "helpMessage": "The SFTP user. Default is root.",
            "default": "root",
        },
        {
            "name": "password",
            "type": "str",
            "required": False,
            "helpMessage": "The SFTP password (optional when the private key is used).",
            "default": None,
        },
        {
            "name": "privateKeyPath",
            "type": "str",
            "required": False,
            "helpMessage": "The path to the RSA private key on the Lemur server (optional).",
            "default": None,
        },
        {
            "name": "privateKeyPass",
            "type": "str",
            "required": False,
            "helpMessage": "The password for the encrypted RSA private key (optional).",
            "default": None,
        },
        {
            "name": "destinationPath",
            "type": "str",
            "required": True,
            "helpMessage": "The SFTP path where certificates will be uploaded.",
            "default": "/etc/nginx/certs",
        },
        {
            "name": "exportFormat",
            "required": True,
            "value": "NGINX",
            "helpMessage": "The export format for certificates.",
            "type": "select",
            "available": ["NGINX", "Apache"],
        },
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        current_app.logger.debug("SFTP destination plugin is started")

        cn = common_name(parse_certificate(body))
        host = self.get_option("host", options)
        port = self.get_option("port", options)
        user = self.get_option("user", options)
        password = self.get_option("password", options)
        ssh_priv_key = self.get_option("privateKeyPath", options)
        ssh_priv_key_pass = self.get_option("privateKeyPass", options)
        dst_path = self.get_option("destinationPath", options)
        export_format = self.get_option("exportFormat", options)

        # prepare files for upload
        files = {cn + ".key": private_key, cn + ".pem": body}

        if cert_chain:
            if export_format == "NGINX":
                # assemble body + chain in the single file
                files[cn + ".pem"] += "\n" + cert_chain

            elif export_format == "Apache":
                # store chain in the separate file
                files[cn + ".ca.bundle.pem"] = cert_chain

        # upload files
        try:
            current_app.logger.debug(
                "Connecting to {0}@{1}:{2}".format(user, host, port)
            )
            ssh = paramiko.SSHClient()

            # allow connection to the new unknown host
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # open the ssh connection
            if password:
                current_app.logger.debug("Using password")
                ssh.connect(host, username=user, port=port, password=password)
            elif ssh_priv_key:
                current_app.logger.debug("Using RSA private key")
                pkey = paramiko.RSAKey.from_private_key_file(
                    ssh_priv_key, ssh_priv_key_pass
                )
                ssh.connect(host, username=user, port=port, pkey=pkey)
            else:
                current_app.logger.error(
                    "No password or private key provided. Can't proceed"
                )
                raise paramiko.ssh_exception.AuthenticationException

            # open the sftp session inside the ssh connection
            sftp = ssh.open_sftp()

            # make sure that the destination path exist
            try:
                current_app.logger.debug("Creating {0}".format(dst_path))
                sftp.mkdir(dst_path)
            except IOError:
                current_app.logger.debug("{0} already exist, resuming".format(dst_path))
            try:
                dst_path_cn = dst_path + "/" + cn
                current_app.logger.debug("Creating {0}".format(dst_path_cn))
                sftp.mkdir(dst_path_cn)
            except IOError:
                current_app.logger.debug(
                    "{0} already exist, resuming".format(dst_path_cn)
                )

            # upload certificate files to the sftp destination
            for filename, data in files.items():
                current_app.logger.debug(
                    "Uploading {0} to {1}".format(filename, dst_path_cn)
                )
                try:
                    with sftp.open(dst_path_cn + "/" + filename, "w") as f:
                        f.write(data)
                except (PermissionError) as permerror:
                    if permerror.errno == 13:
                        current_app.logger.debug(
                            "Uploading {0} to {1} returned Permission Denied Error, making file writable and retrying".format(filename, dst_path_cn)
                        )
                        sftp.chmod(dst_path_cn + "/" + filename, 0o600)
                        with sftp.open(dst_path_cn + "/" + filename, "w") as f:
                            f.write(data)
                # read only for owner, -r--------
                sftp.chmod(dst_path_cn + "/" + filename, 0o400)

            ssh.close()

        except Exception as e:
            current_app.logger.error("ERROR in {0}: {1}".format(e.__class__, e))
            try:
                ssh.close()
            except BaseException:
                pass
