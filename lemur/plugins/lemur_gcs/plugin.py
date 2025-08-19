import os
from typing import Dict, Any, Optional

from google.cloud import storage
from google.oauth2 import service_account
from google.api_core import exceptions as gcs_exceptions

from flask import current_app

from lemur.plugins import lemur_gcs
from lemur.common.defaults import (
    common_name,
    country,
    state,
    location,
    organizational_unit,
    organization,
)
from lemur.common.utils import parse_certificate
from lemur.exceptions import InvalidConfiguration
from lemur.plugins.bases import DestinationPlugin


class GcsDestinationPlugin(DestinationPlugin):
    title = "Google Cloud Storage"
    slug = "gcs-destination"
    description = "Enables the creation of Google Cloud Storage destinations."
    version = lemur_gcs.VERSION
    requires_key = False
    author = "Oleg Dopertchouk"
    author_url = "https://github.com/odopertchouk"
    options = [
        {
            "name": "bucketName",
            "type": "str",
            "required": True,
            "validation": "^.*$",
            "helpMessage": "Name of the bucket to upload the certificate to.",
        },
        {
            "name": "certObjectName",
            "type": "str",
            "default": "{CN}.crt",
            "required": True,
            "validation": "^(([a-zA-Z0-9._-]+|{(CN|OU|O|L|S|C)})+/?)+$",
            "helpMessage": "Valid GCS object path. Support vars: {CN|OU|O|L|S|C}",
        },
        {
            "name": "keyObjectName",
            "type": "str",
            "required": True,
            "default": "{CN}.key.pem",
            "validation": "^(([a-zA-Z0-9._-]+|{(CN|OU|O|L|S|C)})+/?)+$",
            "helpMessage": "Valid GCS object path. Support vars: {CN|OU|O|L|S|C}",
        },
    ]

    def __init__(self, *args, **kwargs):
        self._validate_credentials()
        super(GcsDestinationPlugin, self).__init__(*args, **kwargs)

    def _validate_credentials(self) -> None:
        """Validate that GCS credentials are properly configured"""
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if cred_path is None:
            raise InvalidConfiguration(
                "Required environment variable 'GOOGLE_APPLICATION_CREDENTIALS' is not set in Lemur's environment"
            )
        if not os.path.isfile(cred_path):
            raise InvalidConfiguration(
                "Environment variable 'GOOGLE_APPLICATION_CREDENTIALS' is not pointing to a valid credentials file"
            )

    @staticmethod
    def expand_vars(s: str, cert: Any) -> str:
        cname = common_name(cert)
        cname = cname.replace("*", "wildcard")
        return s.format(
            CN=cname,
            OU=organizational_unit(cert),
            O=organization(cert),  # noqa: E741
            L=location(cert),
            S=state(cert),
            C=country(cert),
        )

    def _create_storage_client(self) -> storage.Client:
        """
        Create and return a Google Cloud Storage client

        :return: Configured storage client
        :raises: InvalidConfiguration if credentials are invalid
        """
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not cred_path or not os.path.isfile(cred_path):
            raise InvalidConfiguration(
                "Valid GOOGLE_APPLICATION_CREDENTIALS file not found"
            )

        credentials = service_account.Credentials.from_service_account_file(cred_path)
        return storage.Client(credentials=credentials)

    def _validate_upload_options(self, options: Dict[str, Any]) -> str:
        """
        Validate required upload options

        :param options: Plugin options dictionary
        :return: Validated bucket name
        :raises: InvalidConfiguration if options are invalid
        """
        bucket_name = self.get_option("bucketName", options)
        if not bucket_name:
            raise InvalidConfiguration("Bucket name is required")
        return bucket_name

    def _generate_object_name(
        self, option_name: str, options: Dict[str, Any], parsed_cert: Any
    ) -> str:
        """
        Generate and validate object name from options and certificate

        :param option_name: Name of the option ('certObjectName' or 'keyObjectName')
        :param options: Plugin options dictionary
        :param parsed_cert: Parsed certificate object
        :return: Validated object name
        :raises: InvalidConfiguration if object name is invalid
        """
        object_name = self.get_option(option_name, options)
        object_name = self.expand_vars(object_name, cert=parsed_cert)

        if not object_name or object_name.startswith("/"):
            raise InvalidConfiguration(f"Invalid object name: {object_name}")

        return object_name

    def _upload_certificate_data(
        self, bucket: storage.Bucket, object_name: str, cert_data: str, bucket_name: str
    ) -> None:
        """
        Upload certificate data to GCS bucket

        :param bucket: GCS bucket object
        :param object_name: Name of the object to create
        :param cert_data: Certificate data to upload
        :param bucket_name: Name of the bucket (for logging)
        :raises: Exception for GCS upload errors
        """
        blob = bucket.blob(object_name)
        current_app.logger.info(
            f"Uploading certificate to bucket: {bucket_name}, object: {object_name}"
        )
        blob.upload_from_string(cert_data)

    def _upload_private_key(
        self,
        bucket: storage.Bucket,
        object_name: str,
        private_key: str,
        bucket_name: str,
    ) -> None:
        """
        Upload private key data to GCS bucket

        :param bucket: GCS bucket object
        :param object_name: Name of the object to create
        :param private_key: Private key data to upload
        :param bucket_name: Name of the bucket (for logging)
        :raises: Exception for GCS upload errors
        """
        blob = bucket.blob(object_name)
        current_app.logger.info(
            f"Uploading private key to bucket: {bucket_name}, object: {object_name}"
        )
        blob.upload_from_string(private_key)

    def upload(
        self,
        name: str,
        body: str,
        private_key: Optional[str],
        cert_chain: str,
        options: Dict[str, Any],
        **kwargs,
    ) -> bool:
        """
        Upload certificate and private key to Google Cloud Storage

        :param name: Certificate name
        :param body: Certificate body
        :param private_key: Private key (optional)
        :param cert_chain: Certificate chain
        :param options: Plugin options
        :return: True if successful
        :raises: InvalidConfiguration, Exception for GCS errors
        """
        current_app.logger.info("Uploading certificate to Google Cloud Storage")

        try:
            # Create storage client and validate options
            storage_client = self._create_storage_client()
            bucket_name = self._validate_upload_options(options)

            # Get bucket (validates bucket exists and we have access)
            bucket = storage_client.bucket(bucket_name)

            # Parse certificate for variable expansion
            parsed_cert = parse_certificate(body)

            # Generate certificate object name and upload certificate
            cert_object_name = self._generate_object_name(
                "certObjectName", options, parsed_cert
            )
            cert_data = body + cert_chain
            self._upload_certificate_data(
                bucket, cert_object_name, cert_data, bucket_name
            )

            # Upload private key if provided
            if private_key:
                key_object_name = self._generate_object_name(
                    "keyObjectName", options, parsed_cert
                )
                self._upload_private_key(
                    bucket, key_object_name, private_key, bucket_name
                )

            current_app.logger.info(
                "Certificate successfully uploaded to Google Cloud Storage"
            )
            return True

        except gcs_exceptions.NotFound as e:
            current_app.logger.error(f"GCS bucket or object not found: {e}")
            raise Exception(f"GCS upload failed - bucket or object not found: {e}")
        except gcs_exceptions.Forbidden as e:
            current_app.logger.error(f"GCS access denied: {e}")
            raise Exception(f"GCS upload failed - access denied: {e}")
        except gcs_exceptions.GoogleAPIError as e:
            current_app.logger.error(f"GCS API error: {e}")
            raise Exception(f"GCS upload failed - API error: {e}")
        except Exception as e:
            current_app.logger.error(f"Unexpected error during GCS upload: {e}")
            raise Exception(f"GCS upload failed: {e}")
