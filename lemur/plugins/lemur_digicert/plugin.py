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
import pem
import requests
import sys
from cryptography import x509
from flask import current_app, g
from lemur.common.utils import validate_conf, convert_pkcs7_bytes_to_pem
from lemur.extensions import metrics
from lemur.plugins import lemur_digicert as digicert
from lemur.plugins.bases import IssuerPlugin, SourcePlugin
from retrying import retry
from requests.packages.urllib3.util.retry import Retry


def log_status_code(r, *args, **kwargs):
    """
    Is a request hook that logs all status codes to the digicert api.

    :param r:
    :param args:
    :param kwargs:
    :return:
    """
    log_data = {
        "reason": (r.reason if r.reason else ""),
        "status_code": r.status_code,
        "url": (r.url if r.url else ""),
    }
    metrics.send("digicert_status_code_{}".format(r.status_code), "counter", 1)
    current_app.logger.info(log_data)


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


def determine_validity_years(years):
    """
    Considering maximum allowed certificate validity period of 397 days, this method should not return
    more than 1 year of validity. Thus changing it to always return 1.
    Lemur will change this method in future to handle validity in months (determine_validity_months)
    instead of years. This will allow flexibility to handle short-lived certificates.

    :param years:
    :return: 1
    """
    return 1


def determine_end_date(end_date):
    """
    Determine appropriate end date

    :param end_date:
    :return: validity_end
    """
    default_days = current_app.config.get("DIGICERT_DEFAULT_VALIDITY_DAYS", 397)
    max_validity_end = arrow.utcnow().shift(days=current_app.config.get("DIGICERT_MAX_VALIDITY_DAYS", default_days))

    if not end_date:
        end_date = arrow.utcnow().shift(days=default_days)

    if end_date > max_validity_end:
        end_date = max_validity_end
    return end_date


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
        data["validity_years"] = determine_validity_years(options.get("validity_years"))
    elif options.get("validity_end"):
        data["custom_expiration_date"] = determine_end_date(options.get("validity_end")).format("YYYY-MM-DD")
        # check if validity got truncated. If resultant validity is not equal to requested validity, it just got truncated
        if data["custom_expiration_date"] != options.get("validity_end").format("YYYY-MM-DD"):
            log_validity_truncation(options, f"{__name__}.{sys._getframe().f_code.co_name}")
    else:
        data["validity_years"] = determine_validity_years(0)

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
    :return: data
    """

    if options.get("validity_years"):
        validity_end = determine_end_date(arrow.utcnow().shift(years=options["validity_years"]))
    elif options.get("validity_end"):
        validity_end = determine_end_date(options.get("validity_end"))
        # check if validity got truncated. If resultant validity is not equal to requested validity, it just got truncated
        if validity_end != options.get("validity_end"):
            log_validity_truncation(options, f"{__name__}.{sys._getframe().f_code.co_name}")
    else:
        validity_end = determine_end_date(False)

    data = {
        "profile_name": current_app.config.get("DIGICERT_CIS_PROFILE_NAMES", {}).get(options['authority'].name),
        "common_name": options["common_name"],
        "additional_dns_names": get_additional_names(options),
        "csr": csr,
        "signature_hash": signature_hash(options.get("signing_algorithm")),
        "validity": {
            "valid_to": validity_end.format("YYYY-MM-DDTHH:mm:ss") + "Z"
        },
        "organization": {
            "name": options["organization"],
        },
    }
    #  possibility to default to a SIGNING_ALGORITHM for a given profile
    if current_app.config.get("DIGICERT_CIS_SIGNING_ALGORITHMS", {}).get(options['authority'].name):
        data["signature_hash"] = current_app.config.get("DIGICERT_CIS_SIGNING_ALGORITHMS", {}).get(
            options['authority'].name)

    return data


def log_validity_truncation(options, function):
    log_data = {
        "cn": options["common_name"],
        "creator": g.user.username
    }
    metrics.send("digicert_validity_truncated", "counter", 1, metric_tags=log_data)

    log_data["function"] = function
    log_data["message"] = "Digicert Plugin truncated the validity of certificate"
    current_app.logger.info(log_data)


def handle_response(response):
    """
    Handle the DigiCert API response and any errors it might have experienced.
    :param response:
    :return:
    """
    if response.status_code > 399:
        raise Exception("DigiCert rejected request with the error:" + response.json()["errors"][0]["message"])

    return response.json()


def reset_cis_session(session):
    """
    The current session might be in a bad state with wrong headers.
    Let's attempt to update the session back to the initial state.
    :param session:
    :return:
    """
    session.headers.clear()
    session.headers.update(
        {
            "X-DC-DEVKEY": current_app.config["DIGICERT_CIS_API_KEY"],
            "Content-Type": "application/json",
        }
    )


def handle_cis_response(session, response):
    """
    Handle the DigiCert CIS API response and any errors it might have experienced.
    :param response:
    :return:
    """
    if response.status_code == 404:
        raise Exception("DigiCert: order not in issued state")
    elif response.status_code == 406:
        log_header = session.headers
        log_header.pop("X-DC-DEVKEY")
        reset_cis_session(session)
        raise Exception("DigiCert: wrong header request format: " + str(log_header))
    elif response.status_code > 399:
        raise Exception("DigiCert rejected request with the error: " + response.text)
    if response.url.endswith("download"):
        return response.content
    else:
        return response.json()


@retry(stop_max_attempt_number=10, wait_fixed=1000)
def get_certificate_id(session, base_url, order_id):
    """Retrieve certificate order id from Digicert API."""
    order_url = "{0}/services/v2/order/certificate/{1}".format(base_url, order_id)
    response_data = handle_response(session.get(order_url))
    if response_data["status"] != "issued":
        raise Exception("Order not in issued state.")

    return response_data["certificate"]["id"]


@retry(stop_max_attempt_number=10, wait_fixed=1000)
def get_cis_certificate(session, base_url, order_id):
    """Retrieve certificate order id from Digicert API, including the chain"""
    certificate_url = "{0}/platform/cis/certificate/{1}/download".format(base_url, order_id)
    session.headers.update({"Accept": "application/x-pkcs7-certificates"})
    response = session.get(certificate_url)
    session.headers.pop("Accept")
    response_content = handle_cis_response(session, response)

    cert_chain_pem = convert_pkcs7_bytes_to_pem(response_content)
    if len(cert_chain_pem) < 3:
        raise Exception("Missing the certificate chain")
    return cert_chain_pem


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

        # max_retries applies only to failed DNS lookups, socket connections and connection timeouts,
        # never to requests where data has made it to the server.
        # we Retry we also covers HTTP status code 406, 500, 502, 503, 504
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[406, 500, 502, 503, 504])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

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

    def revoke_certificate(self, certificate, reason):
        """Revoke a Digicert certificate."""
        base_url = current_app.config.get("DIGICERT_URL")

        # make certificate revoke request
        create_url = "{0}/services/v2/certificate/{1}/revoke".format(
            base_url, certificate.external_id
        )

        comments = reason["comments"] if "comments" in reason else ''
        if "crl_reason" in reason:
            comments += '(' + reason["crl_reason"] + ')'

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

        # max_retries applies only to failed DNS lookups, socket connections and connection timeouts,
        # never to requests where data has made it to the server.
        # we Retry we also covers HTTP status code 406, 500, 502, 503, 504
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[406, 500, 502, 503, 504])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

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
            data = handle_cis_response(self.session, response)

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

        # max_retries applies only to failed DNS lookups, socket connections and connection timeouts,
        # never to requests where data has made it to the server.
        # we Retry we also covers HTTP status code 406, 500, 502, 503, 504
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[406, 500, 502, 503, 504])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        super(DigiCertCISIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """Create a DigiCert certificate."""
        base_url = current_app.config.get("DIGICERT_CIS_URL")

        # make certificate request
        create_url = "{0}/platform/cis/certificate".format(base_url)

        data = map_cis_fields(issuer_options, csr)
        response = self.session.post(create_url, data=json.dumps(data))
        data = handle_cis_response(self.session, response)

        # retrieve certificate
        certificate_chain_pem = get_cis_certificate(self.session, base_url, data["id"])

        end_entity = certificate_chain_pem[0]
        intermediate = certificate_chain_pem[1]

        return (
            "\n".join(str(end_entity).splitlines()),
            "\n".join(str(intermediate).splitlines()),
            data["id"],
        )

    def revoke_certificate(self, certificate, reason):
        """Revoke a Digicert certificate."""
        base_url = current_app.config.get("DIGICERT_CIS_URL")

        # make certificate revoke request
        revoke_url = "{0}/platform/cis/certificate/{1}/revoke".format(
            base_url, certificate.external_id
        )
        metrics.send("digicert_revoke_certificate_success", "counter", 1)

        comments = reason["comments"] if "comments" in reason else ''
        if "crl_reason" in reason:
            comments += '(' + reason["crl_reason"] + ')'
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
