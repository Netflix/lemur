"""
.. module: lemur.plugins.lemur_digicert.plugin
    :platform: Unix
    :synopsis: This module is responsible for communicating with the DigiCert '
    Advanced API.
    :license: Apache, see LICENSE for more details.

    DigiCert CertCentral (v2 API) Documentation
    https://www.digicert.com/services/v2/documentation

    Original Implementation:
    Chris Dorros, github.com/opendns/lemur-digicert

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json
import arrow
import requests

import pem
from retrying import retry

from flask import current_app

from cryptography import x509

from lemur.extensions import metrics
from lemur.common.utils import validate_conf
from lemur.plugins.bases import IssuerPlugin, SourcePlugin

from lemur.plugins import lemur_digicert as digicert


def log_status_code(r, *args, **kwargs):
    """
    Is a request hook that logs all status codes to the digicert api.

    :param r:
    :param args:
    :param kwargs:
    :return:
    """
    metrics.send("digicert_status_code_{}".format(r.status_code), "counter", 1)


def signature_hash(signing_algorithm):
    """Converts Lemur's signing algorithm into a format DigiCert understands.

    :param signing_algorithm:
    :return: str digicert specific algorithm string
    """
    if not signing_algorithm:
        return current_app.config.get("DIGICERT_DEFAULT_SIGNING_ALGORITHM", "sha256")

    if signing_algorithm == "sha256WithRSA":
        return "sha256"

    elif signing_algorithm == "sha384WithRSA":
        return "sha384"

    elif signing_algorithm == "sha512WithRSA":
        return "sha512"

    raise Exception("Unsupported signing algorithm.")


def determine_validity_years(end_date):
    """Given an end date determine how many years into the future that date is.

    :param end_date:
    :return: str validity in years
    """
    now = arrow.utcnow()

    if end_date < now.shift(years=+1):
        return 1
    elif end_date < now.shift(years=+2):
        return 2
    elif end_date < now.shift(years=+3):
        return 3

    raise Exception(
        "DigiCert issued certificates cannot exceed three" " years in validity"
    )


def get_additional_names(options):
    """
    Return a list of strings to be added to a SAN certificates.

    :param options:
    :return:
    """
    names = []
    # add SANs if present
    if options.get("extensions"):
        for san in options["extensions"]["sub_alt_names"]["names"]:
            if isinstance(san, x509.DNSName):
                names.append(san.value)
    return names


def map_fields(options, csr):
    """Set the incoming issuer options to DigiCert fields/options.

    :param options:
    :param csr:
    :return: dict or valid DigiCert options
    """
    if not options.get("validity_years"):
        if not options.get("validity_end"):
            options["validity_years"] = current_app.config.get(
                "DIGICERT_DEFAULT_VALIDITY", 1
            )

    data = dict(
        certificate={
            "common_name": options["common_name"],
            "csr": csr,
            "signature_hash": signature_hash(options.get("signing_algorithm")),
        },
        organization={"id": current_app.config.get("DIGICERT_ORG_ID")},
    )

    data["certificate"]["dns_names"] = get_additional_names(options)

    if options.get("validity_years"):
        data["validity_years"] = options["validity_years"]
    else:
        data["custom_expiration_date"] = options["validity_end"].format("YYYY-MM-DD")

    if current_app.config.get("DIGICERT_PRIVATE", False):
        if "product" in data:
            data["product"]["type_hint"] = "private"
        else:
            data["product"] = dict(type_hint="private")

    return data


def map_cis_fields(options, csr):
    """
    MAP issuer options to DigiCert CIS fields/options.

    :param options:
    :param csr:
    :return:
    """
    if not options.get("validity_years"):
        if not options.get("validity_end"):
            options["validity_end"] = arrow.utcnow().shift(
                years=current_app.config.get("DIGICERT_DEFAULT_VALIDITY", 1)
            )
        options["validity_years"] = determine_validity_years(options["validity_end"])
    else:
        options["validity_end"] = arrow.utcnow().shift(
            years=options["validity_years"]
        )

    data = {
        "profile_name": current_app.config.get("DIGICERT_CIS_PROFILE_NAMES", {}).get(options['authority'].name),
        "common_name": options["common_name"],
        "additional_dns_names": get_additional_names(options),
        "csr": csr,
        "signature_hash": signature_hash(options.get("signing_algorithm")),
        "validity": {
            "valid_to": options["validity_end"].format("YYYY-MM-DDTHH:MM") + "Z"
        },
        "organization": {
            "name": options["organization"],
            "units": [options["organizational_unit"]],
        },
    }
    #  possibility to default to a SIGNING_ALGORITHM for a given profile
    if current_app.config.get("DIGICERT_CIS_SIGNING_ALGORITHMS", {}).get(options['authority'].name):
        data["signature_hash"] = current_app.config.get("DIGICERT_CIS_SIGNING_ALGORITHMS", {}).get(options['authority'].name)

    return data


def handle_response(response):
    """
    Handle the DigiCert API response and any errors it might have experienced.
    :param response:
    :return:
    """
    if response.status_code > 399:
        raise Exception(response.json()["errors"][0]["message"])

    return response.json()


def handle_cis_response(response):
    """
    Handle the DigiCert CIS API response and any errors it might have experienced.
    :param response:
    :return:
    """
    if response.status_code > 399:
        raise Exception(response.text)

    return response.json()


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_certificate_id(session, base_url, order_id):
    """Retrieve certificate order id from Digicert API."""
    order_url = "{0}/services/v2/order/certificate/{1}".format(base_url, order_id)
    response_data = handle_response(session.get(order_url))
    if response_data["status"] != "issued":
        raise Exception("Order not in issued state.")

    return response_data["certificate"]["id"]


@retry(stop_max_attempt_number=10, wait_fixed=10000)
def get_cis_certificate(session, base_url, order_id):
    """Retrieve certificate order id from Digicert API."""
    certificate_url = "{0}/platform/cis/certificate/{1}".format(base_url, order_id)
    session.headers.update({"Accept": "application/x-pem-file"})
    response = session.get(certificate_url)

    if response.status_code == 404:
        raise Exception("Order not in issued state.")

    return response.content


class DigiCertSourcePlugin(SourcePlugin):
    """Wrap the Digicert Certifcate API."""

    title = "DigiCert"
    slug = "digicert-source"
    description = "Enables the use of Digicert as a source of existing certificates."
    version = digicert.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        """Initialize source with appropriate details."""
        required_vars = [
            "DIGICERT_API_KEY",
            "DIGICERT_URL",
            "DIGICERT_ORG_ID",
            "DIGICERT_ROOT",
        ]
        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-DC-DEVKEY": current_app.config["DIGICERT_API_KEY"],
                "Content-Type": "application/json",
            }
        )

        self.session.hooks = dict(response=log_status_code)

        super(DigiCertSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self):
        pass


class DigiCertIssuerPlugin(IssuerPlugin):
    """Wrap the Digicert Issuer API."""

    title = "DigiCert"
    slug = "digicert-issuer"
    description = "Enables the creation of certificates by the DigiCert REST API."
    version = digicert.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        required_vars = [
            "DIGICERT_API_KEY",
            "DIGICERT_URL",
            "DIGICERT_ORG_ID",
            "DIGICERT_ORDER_TYPE",
            "DIGICERT_ROOT",
        ]

        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-DC-DEVKEY": current_app.config["DIGICERT_API_KEY"],
                "Content-Type": "application/json",
            }
        )

        self.session.hooks = dict(response=log_status_code)

        super(DigiCertIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """Create a DigiCert certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        base_url = current_app.config.get("DIGICERT_URL")
        cert_type = current_app.config.get("DIGICERT_ORDER_TYPE")

        # make certificate request
        determinator_url = "{0}/services/v2/order/certificate/{1}".format(
            base_url, cert_type
        )
        data = map_fields(issuer_options, csr)
        response = self.session.post(determinator_url, data=json.dumps(data))

        if response.status_code > 399:
            raise Exception(response.json()["errors"][0]["message"])

        order_id = response.json()["id"]

        certificate_id = get_certificate_id(self.session, base_url, order_id)

        # retrieve certificate
        certificate_url = "{0}/services/v2/certificate/{1}/download/format/pem_all".format(
            base_url, certificate_id
        )
        end_entity, intermediate, root = pem.parse(
            self.session.get(certificate_url).content
        )
        return (
            "\n".join(str(end_entity).splitlines()),
            "\n".join(str(intermediate).splitlines()),
            certificate_id,
        )

    def revoke_certificate(self, certificate, comments):
        """Revoke a Digicert certificate."""
        base_url = current_app.config.get("DIGICERT_URL")

        # make certificate revoke request
        create_url = "{0}/services/v2/certificate/{1}/revoke".format(
            base_url, certificate.external_id
        )
        metrics.send("digicert_revoke_certificate", "counter", 1)
        response = self.session.put(create_url, data=json.dumps({"comments": comments}))
        return handle_response(response)

    def get_ordered_certificate(self, pending_cert):
        """ Retrieve a certificate via order id """
        order_id = pending_cert.external_id
        base_url = current_app.config.get("DIGICERT_URL")
        try:
            certificate_id = get_certificate_id(self.session, base_url, order_id)
        except Exception as ex:
            return None
        certificate_url = "{0}/services/v2/certificate/{1}/download/format/pem_all".format(
            base_url, certificate_id
        )
        end_entity, intermediate, root = pem.parse(
            self.session.get(certificate_url).content
        )
        cert = {
            "body": "\n".join(str(end_entity).splitlines()),
            "chain": "\n".join(str(intermediate).splitlines()),
            "external_id": str(certificate_id),
        }
        return cert

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        """ Set the certificate order to canceled """
        base_url = current_app.config.get("DIGICERT_URL")
        api_url = "{0}/services/v2/order/certificate/{1}/status".format(
            base_url, pending_cert.external_id
        )
        payload = {"status": "CANCELED", "note": kwargs.get("note")}
        response = self.session.put(api_url, data=json.dumps(payload))
        if response.status_code == 404:
            # not well documented by Digicert, but either the certificate does not exist or we
            # don't own that order (someone else's order id!).  Either way, we can just ignore it
            # and have it removed from Lemur
            current_app.logger.warning(
                "Digicert Plugin tried to cancel pending certificate {0} but it does not exist!".format(
                    pending_cert.name
                )
            )
        elif response.status_code != 204:
            current_app.logger.debug(
                "{0} code {1}".format(response.status_code, response.content)
            )
            raise Exception(
                "Failed to cancel pending certificate {0}".format(pending_cert.name)
            )

    @staticmethod
    def create_authority(options):
        """Create an authority.

        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "digicert"}
        return current_app.config.get("DIGICERT_ROOT"), "", [role]


class DigiCertCISSourcePlugin(SourcePlugin):
    """Wrap the Digicert CIS Certifcate API."""

    title = "DigiCert"
    slug = "digicert-cis-source"
    description = "Enables the use of Digicert as a source of existing certificates."
    version = digicert.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    additional_options = []

    def __init__(self, *args, **kwargs):
        """Initialize source with appropriate details."""
        required_vars = [
            "DIGICERT_CIS_API_KEY",
            "DIGICERT_CIS_URL",
            "DIGICERT_CIS_ROOTS",
            "DIGICERT_CIS_INTERMEDIATES",
            "DIGICERT_CIS_PROFILE_NAMES",
        ]
        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-DC-DEVKEY": current_app.config["DIGICERT_CIS_API_KEY"],
                "Content-Type": "application/json",
            }
        )

        self.session.hooks = dict(response=log_status_code)

        a = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount("https://", a)

        super(DigiCertCISSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        """Fetch all Digicert certificates."""
        base_url = current_app.config.get("DIGICERT_CIS_URL")

        # make request
        search_url = "{0}/platform/cis/certificate/search".format(base_url)

        certs = []
        page = 1

        while True:
            response = self.session.get(
                search_url, params={"status": ["issued"], "page": page}
            )
            data = handle_cis_response(response)

            for c in data["certificates"]:
                download_url = "{0}/platform/cis/certificate/{1}".format(
                    base_url, c["id"]
                )
                certificate = self.session.get(download_url)

                # normalize serial
                serial = str(int(c["serial_number"], 16))
                cert = {
                    "body": certificate.content,
                    "serial": serial,
                    "external_id": c["id"],
                }
                certs.append(cert)

            if page == data["total_pages"]:
                break

            page += 1
        return certs


class DigiCertCISIssuerPlugin(IssuerPlugin):
    """Wrap the Digicert Certificate Issuing API."""

    title = "DigiCert CIS"
    slug = "digicert-cis-issuer"
    description = "Enables the creation of certificates by the DigiCert CIS REST API."
    version = digicert.VERSION

    author = "Kevin Glisson"
    author_url = "https://github.com/netflix/lemur.git"

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        required_vars = [
            "DIGICERT_CIS_API_KEY",
            "DIGICERT_CIS_URL",
            "DIGICERT_CIS_ROOTS",
            "DIGICERT_CIS_INTERMEDIATES",
            "DIGICERT_CIS_PROFILE_NAMES",
        ]

        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-DC-DEVKEY": current_app.config["DIGICERT_CIS_API_KEY"],
                "Content-Type": "application/json",
            }
        )

        self.session.hooks = dict(response=log_status_code)

        super(DigiCertCISIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """Create a DigiCert certificate."""
        base_url = current_app.config.get("DIGICERT_CIS_URL")

        # make certificate request
        create_url = "{0}/platform/cis/certificate".format(base_url)

        data = map_cis_fields(issuer_options, csr)
        response = self.session.post(create_url, data=json.dumps(data))
        data = handle_cis_response(response)

        # retrieve certificate
        certificate_pem = get_cis_certificate(self.session, base_url, data["id"])

        self.session.headers.pop("Accept")
        end_entity = pem.parse(certificate_pem)[0]

        if "ECC" in issuer_options["key_type"]:
            return (
                "\n".join(str(end_entity).splitlines()),
                current_app.config.get("DIGICERT_ECC_CIS_INTERMEDIATES", {}).get(issuer_options['authority'].name),
                data["id"],
            )

        # By default return RSA
        return (
            "\n".join(str(end_entity).splitlines()),
            current_app.config.get("DIGICERT_CIS_INTERMEDIATES", {}).get(issuer_options['authority'].name),
            data["id"],
        )

    def revoke_certificate(self, certificate, comments):
        """Revoke a Digicert certificate."""
        base_url = current_app.config.get("DIGICERT_CIS_URL")

        # make certificate revoke request
        revoke_url = "{0}/platform/cis/certificate/{1}/revoke".format(
            base_url, certificate.external_id
        )
        metrics.send("digicert_revoke_certificate_success", "counter", 1)
        response = self.session.put(revoke_url, data=json.dumps({"comments": comments}))

        if response.status_code != 204:
            metrics.send("digicert_revoke_certificate_failure", "counter", 1)
            raise Exception("Failed to revoke certificate.")

        metrics.send("digicert_revoke_certificate_success", "counter", 1)

    @staticmethod
    def create_authority(options):
        """Create an authority.

        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "digicert"}
        return current_app.config.get("DIGICERT_CIS_ROOTS", {}).get(options['authority'].name), "", [role]
