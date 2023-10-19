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
from os import path

import paramiko
from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError

from flask import current_app
from lemur.plugins import lemur_sftp
from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate, check_validation
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
            "validation": check_validation(r"^(6553[0-5]|655[0-2][0-9]\d|65[0-4](\d){2}|6[0-4](\d){3}|[1-5](\d){4}|[1-9](\d){0,3})"),
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

    def open_sftp_connection(self, options):
        host = self.get_option("host", options)
        port = self.get_option("port", options)
        user = self.get_option("user", options)
        password = self.get_option("password", options)
        ssh_priv_key = self.get_option("privateKeyPath", options)
        ssh_priv_key_pass = self.get_option("privateKeyPass", options)

        # delete files
        try:
            current_app.logger.debug(
                f"Connecting to {user}@{host}:{port}"
            )
            ssh = paramiko.SSHClient()

            # allow connection to the new unknown host
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

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
                raise AuthenticationException

            # open the sftp session inside the ssh connection
            return ssh.open_sftp(), ssh

        except AuthenticationException as e:
            current_app.logger.error(f"ERROR in {e.__class__}: {e}")
            raise AuthenticationException("Couldn't connect to {0}, due to an Authentication exception.")
        except NoValidConnectionsError as e:
            current_app.logger.error(f"ERROR in {e.__class__}: {e}")
            raise NoValidConnectionsError("Couldn't connect to {0}, possible timeout or invalid hostname")

    # this is called when using this as a default destination plugin
    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        current_app.logger.debug("SFTP destination plugin is started")

        cn = common_name(parse_certificate(body))
        dst_path = self.get_option("destinationPath", options)
        dst_path_cn = dst_path + "/" + cn
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

        self.upload_file(dst_path_cn, files, options)

    # this is called from the acme http challenge
    def upload_acme_token(self, token_path, token, options, **kwargs):

        current_app.logger.debug("SFTP destination plugin is started for HTTP-01 challenge")

        dst_path = self.get_option("destinationPath", options)

        _, filename = path.split(token_path)

        # prepare files for upload
        files = {filename: token}

        self.upload_file(dst_path, files, options)

    # this is called from the acme http challenge
    def delete_acme_token(self, token_path, options, **kwargs):
        dst_path = self.get_option("destinationPath", options)

        _, filename = path.split(token_path)

        # prepare files for upload
        files = {filename: None}

        self.delete_file(dst_path, files, options)

    # here the file is deleted
    def delete_file(self, dst_path, files, options):

        try:
            # open the ssh and sftp sessions
            sftp, ssh = self.open_sftp_connection(options)

            # delete files
            for filename, _ in files.items():
                current_app.logger.debug(
                    f"Deleting {filename} from {dst_path}"
                )
                try:
                    sftp.remove(path.join(dst_path, filename))
                except PermissionError as permerror:
                    if permerror.errno == 13:
                        current_app.logger.debug(
                            "Deleting {} from {} returned Permission Denied Error, making file writable and retrying".format(
                                filename, dst_path)
                        )
                        sftp.chmod(path.join(dst_path, filename), 0o600)
                        sftp.remove(path.join(dst_path, filename))

            ssh.close()
        except (AuthenticationException, NoValidConnectionsError) as e:
            raise e
        except Exception as e:
            current_app.logger.error(f"ERROR in {e.__class__}: {e}")
            try:
                ssh.close()
            except BaseException:
                pass

    # here the file is uploaded for real, this helps to keep this class DRY
    def upload_file(self, dst_path, files, options):

        try:
            # open the ssh and sftp sessions
            sftp, ssh = self.open_sftp_connection(options)

            # split the path into it's segments, so we can create it recursively
            allparts = []
            path_copy = dst_path
            while True:
                parts = path.split(path_copy)
                if parts[0] == path_copy:  # sentinel for absolute paths
                    allparts.insert(0, parts[0])
                    break
                elif parts[1] == path_copy:  # sentinel for relative paths
                    allparts.insert(0, parts[1])
                    break
                else:
                    path_copy = parts[0]
                    allparts.insert(0, parts[1])

            # make sure that the destination path exists, recursively
            remote_path = allparts[0]
            for part in allparts:
                try:
                    if part != "/" and part != "":
                        remote_path = path.join(remote_path, part)
                    sftp.stat(remote_path)
                except OSError:
                    current_app.logger.debug(f"{remote_path} doesn't exist, trying to create it")
                    try:
                        sftp.mkdir(remote_path)
                    except OSError as ioerror:
                        current_app.logger.debug(
                            f"Couldn't create {remote_path}, error message: {ioerror}")

            # upload certificate files to the sftp destination
            for filename, data in files.items():
                current_app.logger.debug(
                    f"Uploading {filename} to {dst_path}"
                )
                try:
                    with sftp.open(path.join(dst_path, filename), "w") as f:
                        f.write(data)
                except PermissionError as permerror:
                    if permerror.errno == 13:
                        current_app.logger.debug(
                            "Uploading {} to {} returned Permission Denied Error, making file writable and retrying".format(
                                filename, dst_path)
                        )
                        sftp.chmod(path.join(dst_path, filename), 0o600)
                        with sftp.open(path.join(dst_path, filename), "w") as f:
                            f.write(data)
                # most likely the upload user isn't the webuser, -rw-r--r--
                sftp.chmod(path.join(dst_path, filename), 0o644)

            ssh.close()

        except (AuthenticationException, NoValidConnectionsError) as e:
            raise e
        except Exception as e:
            current_app.logger.error(f"ERROR in {e.__class__}: {e}")
            try:
                ssh.close()
            except BaseException:
                pass
            message = ''
            if hasattr(e, 'errors'):
                for _, error in e.errors.items():
                    message = error.strerror
                raise Exception(
                    'Couldn\'t upload file to {}, error message: {}'.format(self.get_option("host", options), message))
