import unittest
from unittest.mock import patch, Mock, MagicMock, mock_open

from flask import Flask
from lemur.plugins.lemur_sftp import plugin
from paramiko.ssh_exception import AuthenticationException


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

    def test_failing_ssh_connection(self):
        dst_path = '/var/non-existent'
        files = {'first-file': 'data'}
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}]

        with self.assertRaises(AuthenticationException):
            self.sftp_destination.upload_file(dst_path, files, options)

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_upload_file_single_with_password(self, mock_paramiko):
        dst_path = '/var/non-existent'
        files = {'first-file': 'data'}
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'password', 'value': 'test_password'}]

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.upload_file(dst_path, files, options)

        mock_sftp.open.assert_called_once_with('/var/non-existent/first-file', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_once_with('data')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port='22',
                                            password='test_password')

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_upload_file_multiple_with_key(self, mock_paramiko):
        dst_path = '/var/non-existent'
        files = {'first-file': 'data', 'second-file': 'data2'}
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'privateKeyPath', 'value': '/var/id_rsa'},
                   {'name': 'privateKeyPass', 'value': 'ssh-key-password'}]

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_paramiko.RSAKey.from_private_key_file.return_value = 'ssh-rsa test-key'

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.upload_file(dst_path, files, options)

        mock_sftp.open.assert_called_with('/var/non-existent/second-file', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_with('data2')
        mock_ssh.close.assert_called_once()

        mock_paramiko.RSAKey.from_private_key_file.assert_called_with('/var/id_rsa', 'ssh-key-password')
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port='22',
                                            pkey='ssh-rsa test-key')

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_upload_acme_token(self, mock_paramiko):
        token_path = './well-known/acme-challenge/some-token-path'
        token = 'token-data'
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'password', 'value': 'test_password'},
                   {'name': 'destinationPath', 'value': '/var/destination-path'}]

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.upload_acme_token(token_path, token, options)

        mock_sftp.open.assert_called_once_with('/var/destination-path/some-token-path', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_once_with('token-data')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port='22',
                                            password='test_password')

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_delete_file_with_password(self, mock_paramiko):
        dst_path = '/var/non-existent'
        files = {'first-file': None}
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'password', 'value': 'test_password'}]

        mock_sftp = Mock()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.delete_file(dst_path, files, options)

        mock_sftp.remove.assert_called_once_with('/var/non-existent/first-file')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port='22',
                                            password='test_password')

    @patch("lemur.plugins.lemur_sftp.plugin.paramiko")
    def test_delete_acme_token(self, mock_paramiko):
        token_path = './well-known/acme-challenge/some-token-path'
        options = [{'name': 'host', 'value': 'non-existent'}, {'name': 'port', 'value': '22'},
                   {'name': 'user', 'value': 'test_acme'}, {'name': 'password', 'value': 'test_password'},
                   {'name': 'destinationPath', 'value': '/var/destination-path'}]

        mock_sftp = Mock()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        self.sftp_destination.delete_acme_token(token_path, options)

        mock_sftp.remove.assert_called_once_with('/var/destination-path/some-token-path')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port='22',
                                            password='test_password')
