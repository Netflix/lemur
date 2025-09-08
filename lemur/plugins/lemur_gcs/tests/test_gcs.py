import os
import unittest
from unittest.mock import patch, Mock, MagicMock
from flask import Flask

from lemur.plugins.lemur_gcs import plugin
from lemur.exceptions import InvalidConfiguration


class TestGcsDestinationPlugin(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        # Create Flask app context
        self.app = Flask("lemur_test_gcs")
        self.ctx = self.app.app_context()
        self.ctx.push()

        # Standard test options
        self.test_options = [
            {"name": "bucketName", "value": "test-bucket"},
            {"name": "certObjectName", "value": "{CN}.crt"},
            {"name": "keyObjectName", "value": "{CN}.key.pem"},
        ]

    def tearDown(self):
        """Clean up test fixtures"""
        self.ctx.pop()

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    def test_constructor_success(self, mock_isfile):
        """Test successful plugin initialization with valid credentials"""
        plugin_instance = plugin.GcsDestinationPlugin()
        self.assertIsInstance(plugin_instance, plugin.GcsDestinationPlugin)
        mock_isfile.assert_called_once_with("/path/to/valid/creds.json")

    @patch.dict(os.environ, {}, clear=True)
    def test_constructor_missing_env_var(self):
        """Test plugin initialization fails when GOOGLE_APPLICATION_CREDENTIALS is missing"""
        with self.assertRaises(InvalidConfiguration) as context:
            plugin.GcsDestinationPlugin()
        self.assertIn(
            "Required environment variable 'GOOGLE_APPLICATION_CREDENTIALS' is not set",
            str(context.exception),
        )

    @patch.dict(
        os.environ,
        {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/nonexistent/creds.json"},
    )
    @patch("os.path.isfile", return_value=False)
    def test_constructor_invalid_credentials_file(self, mock_isfile):
        """Test plugin initialization fails when credentials file doesn't exist"""
        with self.assertRaises(InvalidConfiguration) as context:
            plugin.GcsDestinationPlugin()
        self.assertIn(
            "Environment variable 'GOOGLE_APPLICATION_CREDENTIALS' is not pointing to a valid credentials file",
            str(context.exception),
        )

    def test_expand_vars_basic(self):
        """Test variable expansion with basic certificate"""
        # Mock certificate with basic attributes
        mock_cert = MagicMock()

        with patch(
            "lemur.plugins.lemur_gcs.plugin.common_name", return_value="example.com"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.organizational_unit", return_value="IT"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.organization", return_value="Example Corp"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.location", return_value="San Francisco"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.state", return_value="CA"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.country", return_value="US"
        ):

            result = plugin.GcsDestinationPlugin.expand_vars(
                "{CN}-{OU}-{O}.crt", mock_cert
            )
            self.assertEqual(result, "example.com-IT-Example Corp.crt")

    def test_expand_vars_wildcard(self):
        """Test variable expansion with wildcard certificate"""
        mock_cert = MagicMock()

        with patch(
            "lemur.plugins.lemur_gcs.plugin.common_name", return_value="*.example.com"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.organizational_unit", return_value="IT"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.organization", return_value="Example Corp"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.location", return_value="San Francisco"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.state", return_value="CA"
        ), patch(
            "lemur.plugins.lemur_gcs.plugin.country", return_value="US"
        ):

            result = plugin.GcsDestinationPlugin.expand_vars("{CN}.crt", mock_cert)
            self.assertEqual(result, "wildcard.example.com.crt")

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    def test_validate_upload_options_success(self, mock_isfile):
        """Test successful option validation"""
        plugin_instance = plugin.GcsDestinationPlugin()
        plugin_instance.get_option = Mock(return_value="test-bucket")

        bucket_name = plugin_instance._validate_upload_options(self.test_options)
        self.assertEqual(bucket_name, "test-bucket")

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    def test_validate_upload_options_missing_bucket(self, mock_isfile):
        """Test option validation fails with missing bucket name"""
        plugin_instance = plugin.GcsDestinationPlugin()
        plugin_instance.get_option = Mock(return_value=None)

        with self.assertRaises(InvalidConfiguration) as context:
            plugin_instance._validate_upload_options(self.test_options)
        self.assertIn("Bucket name is required", str(context.exception))

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    def test_generate_object_name_success(self, mock_isfile):
        """Test successful object name generation"""
        plugin_instance = plugin.GcsDestinationPlugin()
        plugin_instance.get_option = Mock(return_value="{CN}.crt")
        plugin_instance.expand_vars = Mock(return_value="example.com.crt")

        mock_cert = MagicMock()
        object_name = plugin_instance._generate_object_name(
            "certObjectName", self.test_options, mock_cert
        )

        self.assertEqual(object_name, "example.com.crt")
        plugin_instance.expand_vars.assert_called_once_with("{CN}.crt", cert=mock_cert)

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    def test_generate_object_name_invalid_path(self, mock_isfile):
        """Test object name generation fails with invalid path"""
        plugin_instance = plugin.GcsDestinationPlugin()
        plugin_instance.get_option = Mock(return_value="/invalid/path.crt")
        plugin_instance.expand_vars = Mock(return_value="/invalid/path.crt")

        mock_cert = MagicMock()
        with self.assertRaises(InvalidConfiguration) as context:
            plugin_instance._generate_object_name(
                "certObjectName", self.test_options, mock_cert
            )
        self.assertIn("Invalid object name: /invalid/path.crt", str(context.exception))

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    @patch(
        "lemur.plugins.lemur_gcs.plugin.service_account.Credentials.from_service_account_file"
    )
    @patch("lemur.plugins.lemur_gcs.plugin.storage.Client")
    def test_create_storage_client_success(
        self, mock_client, mock_credentials, mock_isfile
    ):
        """Test successful storage client creation"""
        mock_creds = MagicMock()
        mock_credentials.return_value = mock_creds
        mock_storage_client = MagicMock()
        mock_client.return_value = mock_storage_client

        plugin_instance = plugin.GcsDestinationPlugin()
        client = plugin_instance._create_storage_client()

        mock_credentials.assert_called_once_with("/path/to/valid/creds.json")
        mock_client.assert_called_once_with(credentials=mock_creds)
        self.assertEqual(client, mock_storage_client)

    @patch.dict(
        os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/valid/creds.json"}
    )
    @patch("os.path.isfile", return_value=True)
    @patch("lemur.plugins.lemur_gcs.plugin.current_app")
    def test_upload_certificate_data(self, mock_app, mock_isfile):
        """Test certificate data upload"""
        mock_bucket = MagicMock()
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        plugin_instance = plugin.GcsDestinationPlugin()
        plugin_instance._upload_certificate_data(
            mock_bucket, "test.crt", "cert-data", "test-bucket"
        )

        mock_bucket.blob.assert_called_once_with("test.crt")
        mock_blob.upload_from_string.assert_called_once_with("cert-data")
        mock_app.logger.info.assert_called_once()


if __name__ == "__main__":
    unittest.main()
