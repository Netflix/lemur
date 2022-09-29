from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
import hvac
import os

from lemur.common.utils import parse_certificate
from lemur.common.defaults import common_name, issuer, not_before
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins import lemur_gcp as gcp


class GCPDestinationPlugin(DestinationPlugin):
    title = "GCP"
    slug = "gcp-destination"
    version = gcp.VERSION
    description = "Allow the uploading of certificates to GCP"
    author = "Mitch Cail"
    author_url = "https://github.com/Datadog/lemur"

    options = [
        {
            "name": "projectID",
            "type": "str",
            "required": True,
            "helpMessage": "GCP Project ID",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "required": True,
            "available": ["vault", "serviceAccountToken"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "vaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        },
        {
            "name": "serviceAccountTokenPath",
            "type": "str",
            "required": False,
            "helpMessage": "Path to vault secret",
        }
    ]

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        try:
            ssl_certificate_body = {
                "name": self._certificate_name(body),
                "certificate": body,
                "description": "",
                "private_key": private_key,
            }
            credentials = self._get_gcp_credentials(options)
            return self._insert_gcp_certificate(
                self.get_option("projectID", options),
                ssl_certificate_body,
                credentials,
            )

        except Exception as e:
            current_app.logger.error(
                f"Issue with uploading {name} to GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue uploading certificate to GCP: {e}")

    def _insert_gcp_certificate(self, project_id, ssl_certificate_body, credentials):
        return ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )

    def _get_gcp_credentials(self, options):
        if self.get_option('authenticationMethod', options) == "vault":
            # make a request to vault for GCP token
            return self._get_gcp_credentials_from_vault(options)
        elif self.get_option('authenticationMethod', options) == "serviceAccountToken":
            if self.get_option('serviceAccountTokenPath', options) is not None:
                return service_account.Credentials.from_service_account_file(
                    self.get_option('serviceAccountTokenPath', options)
                )

        raise Exception("No supported way to authenticate with GCP")

    def _get_gcp_credentials_from_vault(self, options):
        service_token = hvac.Client(os.environ['VAULT_ADDR']) \
            .secrets.gcp \
            .generate_oauth2_access_token(
            roleset="",
            mount_point=f"{self.get_option('vaultMountPoint', options)}"
        )["data"]["token"].rstrip(".")

        credentials = Credentials(service_token)

        return credentials

    def _certificate_name(self, body):
        """
        We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
        The cert name will follow the convention "ssl-{Cert CN}-{Date Issued}-{Issuer}"
        """
        cert = parse_certificate(body)
        cn = common_name(cert)
        authority = issuer(cert)
        issued_on = not_before(cert).date()

        cert_name = f"ssl-{cn}-{authority}-{issued_on}"

        return self._modify_cert_name_for_gcp(cert_name)

    def _modify_cert_name_for_gcp(self, cert_name):
        # Modify the cert name to comply with GCP naming convention
        gcp_name = cert_name.replace('.', '-')
        gcp_name = gcp_name.replace('*', "star")
        gcp_name = gcp_name.lower()
        gcp_name = gcp_name[:63]
        gcp_name = gcp_name.rstrip('.*-')

        return gcp_name
