"""
.. module: lemur.plugins.lemur_cfssl.plugin
    :platform: Unix
    :synopsis: This module is responsible for communicating with the CFSSL private CA.
    :copyright: (c) 2018 by Thomson Reuters
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Charles Hendrie <chad.hendrie@tr.com>
"""

import json
import requests
import base64
import hmac
import hashlib

from flask import current_app

from lemur.common.utils import parse_certificate
from lemur.common.utils import get_authority_key
from lemur.constants import CRLReason
from lemur.plugins.bases import IssuerPlugin
from lemur.plugins import lemur_cfssl as cfssl
from lemur.extensions import metrics


class CfsslIssuerPlugin(IssuerPlugin):
    title = "CFSSL"
    slug = "cfssl-issuer"
    description = "Enables the creation of certificates by CFSSL private CA"
    version = cfssl.VERSION

    author = "Charles Hendrie"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        super().__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates a CFSSL certificate.

        :param csr:
        :param issuer_options:
        :return:
        """
        current_app.logger.info(
            f"Requesting a new cfssl certificate with csr: {csr}"
        )

        url = "{}{}".format(current_app.config.get("CFSSL_URL"), "/api/v1/cfssl/sign")

        data = {"certificate_request": csr}
        data = json.dumps(data)

        try:
            hex_key = current_app.config.get("CFSSL_KEY")
            key = bytes.fromhex(hex_key)
        except (ValueError, NameError, TypeError):
            # unable to find CFSSL_KEY in config, continue using normal sign method
            pass
        else:
            data = data.encode()

            token = base64.b64encode(
                hmac.new(key, data, digestmod=hashlib.sha256).digest()
            )
            data = base64.b64encode(data)

            data = json.dumps(
                {"token": token.decode("utf-8"), "request": data.decode("utf-8")}
            )

            url = "{}{}".format(
                current_app.config.get("CFSSL_URL"), "/api/v1/cfssl/authsign"
            )
        response = self.session.post(
            url, data=data.encode(encoding="utf_8", errors="strict")
        )
        if response.status_code > 399:
            metrics.send("cfssl_create_certificate_failure", "counter", 1)
            raise Exception("Error creating cert. Please check your CFSSL API server")
        response_json = json.loads(response.content.decode("utf_8"))
        cert = response_json["result"]["certificate"]
        parsed_cert = parse_certificate(cert)
        metrics.send("cfssl_create_certificate_success", "counter", 1)
        return (
            cert,
            current_app.config.get("CFSSL_INTERMEDIATE"),
            parsed_cert.serial_number,
        )

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        name = "cfssl_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        return current_app.config.get("CFSSL_ROOT"), "", [role]

    def revoke_certificate(self, certificate, reason):
        """Revoke a CFSSL certificate."""
        base_url = current_app.config.get("CFSSL_URL")
        create_url = f"{base_url}/api/v1/cfssl/revoke"

        crl_reason = CRLReason.unspecified
        if "crl_reason" in reason:
            crl_reason = CRLReason[reason["crl_reason"]]

        data = (
            '{"serial": "'
            + certificate.external_id
            + '","authority_key_id": "'
            + get_authority_key(certificate.body)
            + '", "reason": "'
            + crl_reason.name
            + '"}'
        )
        current_app.logger.debug(f"Revoking cert: {data}")
        response = self.session.post(
            create_url, data=data.encode(encoding="utf_8", errors="strict")
        )
        if response.status_code > 399:
            metrics.send("cfssl_revoke_certificate_failure", "counter", 1)
            raise Exception("Error revoking cert. Please check your CFSSL API server")
        metrics.send("cfssl_revoke_certificate_success", "counter", 1)
        return response.json()
