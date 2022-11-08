from flask import current_app
from google.api_core import exceptions

from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins import lemur_gcp as gcp
from lemur.plugins.lemur_gcp import auth, certificates
from lemur.plugins.lemur_gcp.endpoints import fetch_target_proxies, update_target_proxy_default_cert, \
    update_target_proxy_sni_certs


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
            "name": "region",
            "type": "str",
            "helpMessage": "Scopes the certificate to a region, if supplied. If no region is given, this will "
                           "upload certificates as a global resource."
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

    def __init__(self, *args, **kwargs):
        super(GCPDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        try:
            ssl_certificate_body = {
                "name": certificates.get_name(body),
                "certificate": certificates.full_ca(body, cert_chain),
                "description": "",
                "private_key": private_key,
            }
            credentials = auth.get_gcp_credentials(self, options)
            return certificates.insert_certificate(
                self.get_option("projectID", options),
                ssl_certificate_body,
                credentials,
                self.get_option("region", options),
            )
        except exceptions.AlreadyExists:
            pass
        except Exception as e:
            current_app.logger.error(
                f"Issue with uploading {name} to GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue uploading certificate to GCP: {e}")


class GCPSourcePlugin(SourcePlugin):
    title = "GCP"
    slug = "gcp-source"
    description = "Discovers all SSL certificates and HTTPs target proxies (global) / L7 and SSL target proxies / L4"
    version = gcp.VERSION

    author = "Henry Wang"
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

    def __init__(self, *args, **kwargs):
        super(GCPSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            return certificates.fetch_all(project_id, credentials)
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificates from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificates from GCP: {e}")

    def get_certificate_by_name(self, certificate_name, options):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            return certificates.fetch_by_name(project_id, credentials, certificate_name)
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificate by name from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching certificate from GCP: {e}")

    def get_endpoints(self, options, **kwargs):
        try:
            credentials = auth.get_gcp_credentials(self, options)
            project_id = self.get_option("projectID", options)
            endpoints = fetch_target_proxies(project_id, credentials)
            return endpoints
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching endpoints from GCP. Action failed with the following log: {e}",
                exc_info=True,
            )
            raise Exception(f"Issue fetching endpoints from GCP: {e}")

    def update_endpoint(self, endpoint, certificate):
        options = endpoint.source.options
        credentials = auth.get_gcp_credentials(self, options)
        project_id = self.get_option("projectID", options)
        update_target_proxy_default_cert(project_id, credentials, endpoint, certificate)

    def replace_sni_certificate(self, endpoint, old_cert, new_cert):
        options = endpoint.source.options
        credentials = auth.get_gcp_credentials(self, options)
        project_id = self.get_option("projectID", options)
        update_target_proxy_sni_certs(project_id, credentials, endpoint, old_cert, new_cert)
