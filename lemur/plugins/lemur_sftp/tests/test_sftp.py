import unittest
from unittest.mock import patch, Mock, MagicMock, mock_open

from flask import Flask
from lemur.plugins.lemur_sftp import plugin


class TestSftp(unittest.TestCase):
    def setUp(self):
        self.sftp_destination = plugin.SFTPDestinationPlugin()
        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = Flask('lemur_test_sftp')
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_upload_file_single_with_password(self, mock_paramiko):
        dst_path = '/tmp/non-existant'
        files = {'first-file': 'data'}
        options = [{'name': 'host', 'value': 'non-existant'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'password', 'value': 'test_password'}]

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.upload_file(dst_path, files, options)

        mock_sftp.open.assert_called_once()
        handle = mock_sftp.open()
        handle.write.assert_called_once_with('data')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existant', username='test_acme', port='22',
                                            password='test_password')

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_upload_file_multiple_with_key(self, mock_paramiko):
        dst_path = '/tmp/non-existant'
        files = {'first-file': 'data', 'second-file': 'data2'}
        options = [{'name': 'host', 'value': 'non-existant'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'privateKeyPath', 'value': '/tmp/id_rsa'},
                   {'name': 'privateKeyPass', 'value': 'ssh-key-password'}]

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_paramiko.RSAKey.from_private_key_file.return_value = 'ssh-rsa test-key'

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.upload_file(dst_path, files, options)

        mock_sftp.open.assert_called()
        handle = mock_sftp.open()
        handle.write.assert_called_with('data2')
        mock_ssh.close.assert_called_once()

        mock_paramiko.RSAKey.from_private_key_file.assert_called_with('/tmp/id_rsa', 'ssh-key-password')
        mock_ssh.connect.assert_called_with('non-existant', username='test_acme', port='22',
                                            pkey='ssh-rsa test-key')
