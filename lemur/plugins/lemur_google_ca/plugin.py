"""
.. module: lemur.plugins.lemur_google_ca.plugin
    :platform: Unix
    :synopsis: This module is responsible for creating certificates with the Google CA API '
    :license: Apache, see LICENSE for more details.

    Google CA (v2 API) Documentation
    https://cloud.google.com/certificate-authority-service/docs/reference/rest

    This plugin requires following packages:
    - google-cloud-private-ca
    - protobuf
    - types-protobuf (for mypy)
    Make sure to add these to `requirements.in`

    The plugin requires `GOOGLE_ACCOUNT_CREDENTIALS` config variable, which should point at the file containing
    credentials that Lemur is using to connect to Google Cloud Platform.

    IAM permissions:
    To issue a certificate, Lemur would need permission `privateca.certificates.create`
    for the specified Certifiate authority

    To revoke a certificate, Lemur would need permission `privateca.certificates.update`
    for the specified Certifiate authority

    To add a Google-based CA, Lemur would need permission `privateca.certificateAuthorities.get`

    This can be achieved by assigning `roles/privateca.certificateAuthorityViewer` and `
    roles/privateca.certificateManager` to Lemur's service account, or by using a custom role.

.. moduleauthor:: Oleg Dopertchouk <odopertchouk@squarespace.com>
"""
import json
import re
import uuid
from typing import Optional

import google.cloud.security.privateca_v1 as privateca

import arrow
from flask import current_app
from google.oauth2 import service_account
from google.protobuf import duration_pb2

from lemur.constants import CRLReason
from lemur.common.utils import validate_conf
import lemur.plugins.lemur_google_ca
from lemur.plugins.bases import IssuerPlugin

SECONDS_PER_YEAR = 365 * 24 * 60 * 60


def get_duration(options):
    """
    Deduce certificate duration from options
    """
    validity_end = options.get("validity_end")
    if validity_end:
        return int((validity_end - arrow.utcnow()).total_seconds())
    else:
        return options.get("validity_years", 1) * SECONDS_PER_YEAR


def generate_certificate_id(common_name) -> str:
    """
    Generates a readable unique id for a cert based on cert's CN
    """
    name = common_name.lower().strip()
    name = re.sub(r'[^a-z0-9-]', '_', name)
    name = name[:50]  # leave space for random id
    return f"{name}-{uuid.uuid4().hex}"[:63]  # Truncate to 63 characters, to fit the api constraints


def fetch_authority(ca_path: str) -> tuple[str, str]:
    client = create_ca_client()
    resp = client.get_certificate_authority(name=ca_path)
    if resp.state != privateca.CertificateAuthority.State.ENABLED:
        raise Exception(f"The CA {ca_path} is not enabled")
    certs = list(resp.pem_ca_certificates)
    ca_pem = certs[0]
    ca_chain = '\n'.join(certs[1:])
    return ca_pem, ca_chain


def create_ca_client():
    """
    Creates a client for accessing GCP API based on credentials supplied in application config.
    """
    return privateca.CertificateAuthorityServiceClient(
        credentials=service_account.Credentials.from_service_account_file(
            current_app.config['GOOGLE_APPLICATION_CREDENTIALS']
        )
    )


class GoogleCaIssuerPlugin(IssuerPlugin):
    title = "Google CA"
    slug = "googleca-issuer"
    description = "Enables the creation of certificates by Google CA"
    version = lemur.plugins.lemur_google_ca.VERSION

    author = "Oleg Dopertchouk"
    author_url = "https://github.com/odopertchouk"

    options = [
        {
            "name": "Project",
            "type": "str",
            "required": True,
            "validation": "(?i)^[a-zA-Z_0-9.-]+$",
            "helpMessage": "Must be a valid GCP project name!",
        },
        {
            "name": "Location",
            "type": "str",
            "required": True,
            "validation": "(?i)^[a-z0-9-]+$",
            "helpMessage": "Must be a valid GCP location name!",
        },
        {
            "name": "CAPool",
            "type": "str",
            "required": True,
            "validation": "(?i)^[a-zA-Z_0-9.-]+$",
            "helpMessage": "Must be a valid GCP name!",
        },
        {
            "name": "CAName",
            "type": "str",
            "required": True,
            "validation": "(?i)^[a-zA-Z_0-9.-]+$",
            "helpMessage": "Must be a valid GCP name!",
        },
    ]

    def __init__(self, *args, **kwargs):
        """Initialize source with appropriate details."""
        required_vars = [
            "GOOGLE_APPLICATION_CREDENTIALS",
        ]
        validate_conf(current_app, required_vars)

    def create_certificate(self, csr, options) -> tuple[str, str, str]:
        """
        :param csr: Certificate Signing Request to turn into a certificate
        :param options: Options passed from the UI (validated by CertificateInputSchema)
        """
        authority = options['authority']
        if not authority:
            raise ValueError("Certificate  requires a signer CA to be specified")
        if authority.plugin_name != GoogleCaIssuerPlugin.slug:
            raise ValueError("Certificate must be created by Google CA")
        ca_options = {opt['name']: opt['value'] for opt in json.loads(authority.options)}
        ca_path = f"projects/{ca_options['Project']}" \
                  f"/locations/{ca_options['Location']}" \
                  f"/caPools/{ca_options['CAPool']}"
        lifetime = get_duration(options)

        client = create_ca_client()
        request = privateca.CreateCertificateRequest(
            parent=ca_path,
            certificate=privateca.Certificate(
                pem_csr=csr,
                lifetime=duration_pb2.Duration(seconds=lifetime)
            ),
            certificate_id=generate_certificate_id(options['common_name']),
            issuing_certificate_authority_id=ca_options['CAName']
        )
        resp = client.create_certificate(request)
        cert_pem = resp.pem_certificate
        chain_pem = '\n'.join(resp.pem_certificate_chain)
        ext_id = request.certificate_id
        return cert_pem, chain_pem, ext_id

    def create_authority(self, options: dict) -> tuple[str, Optional[str], str, list[dict]]:
        """
        :param options: Plugin options as specified in AuthorityInputSchema
        :return body, private_key, chain, roles
        """
        plugin_options = {opt['name']: opt.get('value') for opt in options.get('plugin', {}).get('plugin_options', [])}

        ca_name = options["name"]
        ca_path = f"projects/{plugin_options['Project']}" \
                  f"/locations/{plugin_options['Location']}" \
                  f"/caPools/{plugin_options['CAPool']}" \
                  f"/certificateAuthorities/{plugin_options['CAName']}"
        ca_pem, chain_pem = fetch_authority(ca_path)

        name = f"googleca_{ca_name}_admin"
        role = {"username": "", "password": "", "name": name}
        return ca_pem, "", chain_pem, [role]

    def revoke_certificate(self, certificate, reason):
        authority = certificate.authority
        if not authority:
            raise ValueError("Certificate  requires a signer CA to be specified")
        if authority.plugin_name != GoogleCaIssuerPlugin.slug:
            raise ValueError("Certificate must be created by Google CA")

        ca_options = {opt['name']: opt['value'] for opt in json.loads(authority.options)}
        ca_path = f"projects/{ca_options['Project']}" \
                  f"/locations/{ca_options['Location']}" \
                  f"/caPools/{ca_options['CAPool']}" \
                  f"/certificates/{certificate.external_id}"
        crl_reason = CRLReason.unspecified
        if "crl_reason" in reason:
            crl_reason = CRLReason[reason["crl_reason"]]

        client = create_ca_client()
        request = privateca.RevokeCertificateRequest(
            name=ca_path,
            reason=crl_reason,
        )
        response = client.revoke_certificate(request=request)
        return response
