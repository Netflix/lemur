import json
import sys

import arrow
import requests
from flask import current_app
from retrying import retry
from urllib3.util.retry import Retry

from lemur.certificates.service import get_ekus
from lemur.common.utils import validate_conf, get_key_type_from_certificate
from lemur.constants import CRLReason
from lemur.extensions import metrics
from lemur.plugins import lemur_entrust as entrust
from lemur.plugins.bases import IssuerPlugin, SourcePlugin


def log_status_code(r, *args, **kwargs):
    """
    Is a request hook that logs all status codes to the ENTRUST api.

    :param r:
    :param args:
    :param kwargs:
    :return:
    """
    if r.status_code != 200:
        log_data = {
            "reason": (r.reason if r.reason else ""),
            "status_code": r.status_code,
            "url": (r.url if r.url else ""),
        }
        metrics.send(f"entrust_status_code_{r.status_code}", "counter", 1)
        current_app.logger.info(log_data)


def determine_end_date(end_date):
    """
    Determine appropriate end date
    :param end_date:
    :return: validity_end as string
    """
    # ENTRUST only allows 13 months of max certificate duration
    max_validity_end = arrow.utcnow().shift(years=1, months=+1)

    if not end_date:
        end_date = max_validity_end
    elif end_date > max_validity_end:
        end_date = max_validity_end
    return end_date.format('YYYY-MM-DD')


def process_options(options, client_id, csr=None):
    """
    Processes and maps the incoming issuer options to fields/options that
    Entrust understands

    :param options:
    :param csr:
    :return: dict of valid entrust options
    """
    # if there is a config variable ENTRUST_PRODUCT_<upper(authority.name)>
    # take the value as Cert product-type
    # else default to "STANDARD_SSL"
    authority = options.get("authority").name.upper()
    # STANDARD_SSL (cn=domain, san=www.domain),
    # ADVANTAGE_SSL (cn=domain, san=[www.domain, one_more_option]),
    # WILDCARD_SSL (unlimited sans, and wildcard)
    product_type = current_app.config.get(f"ENTRUST_PRODUCT_{authority}", "STANDARD_SSL")

    if options.get("validity_end"):
        validity_end = determine_end_date(options.get("validity_end"))
    else:
        validity_end = determine_end_date(False)

    tracking_data = {
        "requesterName": current_app.config.get("ENTRUST_NAME"),
        "requesterEmail": current_app.config.get("ENTRUST_EMAIL"),
        "requesterPhone": current_app.config.get("ENTRUST_PHONE")
    }
    eku = "SERVER_AND_CLIENT_AUTH"
    if current_app.config.get("ENTRUST_INFER_EKU", False) and csr:
        ekus = get_ekus(csr)
        client_auth = any(usage._name == 'clientAuth' for usage in ekus.value)
        server_auth = any(usage._name == 'serverAuth' for usage in ekus.value)

        if client_auth and not server_auth:
            eku = "CLIENT_AUTH"
        elif server_auth and not client_auth:
            eku = "SERVER_AUTH"

    data = {
        "signingAlg": "SHA-2",
        "certType": product_type,
        "certExpiryDate": validity_end,
        "tracking": tracking_data,
        "org": options.get("organization"),
        "clientId": client_id,
        "eku": eku,
    }
    return data


@retry(stop_max_attempt_number=5, wait_fixed=1000)
def get_client_id(session, organization):
    """
    Helper function for looking up clientID based on Organization and parsing the response.
    :param session:
    :param organization: the validated org with Entrust, for instance "Company, Inc."
    :return: ClientID
    :raise Exception:
    """

    # get the organization ID
    url = current_app.config.get("ENTRUST_URL") + "/organizations"
    try:
        response = session.get(url, timeout=(15, 40))
    except requests.exceptions.Timeout:
        raise Exception("Timeout for Getting Organizations")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error for Getting Organization {e}")

    # parse the response
    try:
        d = json.loads(response.content)
    except ValueError:
        # catch an empty json object here
        d = {'response': 'No detailed message'}

    if 'status' in d and d['status'] >= 300:
        error_messages = d['errors']
        raise Exception(f"Error for Getting Organization {error_messages}")

    if 'organizations' not in d:
        raise Exception("Error for Getting Organization: no org returned")

    found = False
    for y in d["organizations"]:
        if y["name"] == organization and y["verificationStatus"] == 'APPROVED':
            found = True
            client_id = y["clientId"]
    if found:
        return client_id
    else:
        raise Exception(f"Error on Organization - Use one from the list: {d['organizations']}")


def handle_response(my_response):
    """
    Helper function for parsing responses from the Entrust API.
    :param my_response:
    :return: :raise Exception:
    """
    msg = {
        200: "The request had the validateOnly flag set to true and validation was successful.",
        201: "Certificate created",
        202: "Request accepted and queued for approval",
        400: "Invalid request parameters",
        404: "Unknown jobId",
        429: "Too many requests"
    }

    try:
        data = json.loads(my_response.content)
    except ValueError:
        # catch an empty jason object here
        data = {'response': 'No detailed message'}
    status_code = my_response.status_code
    if status_code > 399:
        raise Exception(f"ENTRUST error: {msg.get(status_code, status_code)}\n{data['errors']}")

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Response",
        "status": status_code,
        "response": data
    }
    current_app.logger.info(log_data)
    if data == {'response': 'No detailed message'}:
        # status if no data
        return status_code
    else:
        #  return data from the response
        return data


@retry(stop_max_attempt_number=3, wait_fixed=5000)
def order_and_download_certificate(session, url, data):
    """
    Helper function to place a certificacte order and download it
    :param session:
    :param url: Entrust endpoint url
    :param data: CSR, and the required order details, such as validity length
    :return: the cert chain
    :raise Exception:
    """
    try:
        response = session.post(url, json=data, timeout=(15, 40))
    except requests.exceptions.Timeout:
        raise Exception("Timeout for POST")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error for POST {e}")

    return handle_response(response)


class EntrustIssuerPlugin(IssuerPlugin):
    title = "Entrust"
    slug = "entrust-issuer"
    description = "Enables the creation of certificates by ENTRUST"
    version = entrust.VERSION

    author = "sirferl"
    author_url = "https://github.com/sirferl/lemur"

    options = [
        {
            "name": "staging_account",
            "type": "bool",
            "required": False,
            "helpMessage": "Set to True if this is an Entrust staging account.",
            "default": False,
        }
    ]

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        required_vars = [
            "ENTRUST_API_USER",
            "ENTRUST_API_PASS",
            "ENTRUST_URL",
            "ENTRUST_ROOT",
            "ENTRUST_NAME",
            "ENTRUST_EMAIL",
            "ENTRUST_PHONE",
        ]
        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        cert_file = current_app.config.get("ENTRUST_API_CERT", None)
        key_file = current_app.config.get("ENTRUST_API_KEY", None)
        user = current_app.config.get("ENTRUST_API_USER")
        password = current_app.config.get("ENTRUST_API_PASS")
        if cert_file and key_file:
            # API key can be used with Client TLS certificate
            self.session.cert = (cert_file, key_file)
        self.session.auth = (user, password)
        self.session.hooks = dict(response=log_status_code)
        # self.session.config['keep_alive'] = False

        # max_retries applies only to failed DNS lookups, socket connections and connection timeouts,
        # never to requests where data has made it to the server.
        # we Retry we also covers HTTP status code 500, 502, 503, 504
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        super().__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates an Entrust certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "message": "Requesting options",
            "options": issuer_options
        }
        current_app.logger.info(log_data)

        if current_app.config.get("ENTRUST_USE_DEFAULT_CLIENT_ID"):
            # The ID of the primary client is 1.
            client_id = 1
        else:
            client_id = get_client_id(self.session, issuer_options.get("organization"))
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "message": f"Organization id: {client_id}"
        }
        current_app.logger.info(log_data)

        url = current_app.config.get("ENTRUST_URL") + "/certificates"

        data = process_options(issuer_options, client_id, csr)
        data["csr"] = csr

        response_dict = order_and_download_certificate(self.session, url, data)

        external_id = response_dict['trackingId']
        cert = response_dict['endEntityCert']
        if len(response_dict['chainCerts']) < 2:
            # certificate signed by CA directly, no ICA included in the chain
            chain = None
        else:
            chain = response_dict['chainCerts'][1]

        if current_app.config.get("ENTRUST_CROSS_SIGNED_RSA_L1K") and get_key_type_from_certificate(cert) == "RSA2048":
            chain = current_app.config.get("ENTRUST_CROSS_SIGNED_RSA_L1K")
        if current_app.config.get("ENTRUST_CROSS_SIGNED_ECC_L1F") and get_key_type_from_certificate(cert) == "ECCPRIME256V1":
            chain = current_app.config.get("ENTRUST_CROSS_SIGNED_ECC_L1F")

        log_data["message"] = "Received Chain"
        log_data["options"] = f"chain: {chain}"
        current_app.logger.info(log_data)

        return cert, chain, external_id

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def revoke_certificate(self, certificate, reason):
        """Revoke an Entrust certificate."""
        base_url = current_app.config.get("ENTRUST_URL")

        # make certificate revoke request
        revoke_url = f"{base_url}/certificates/{certificate.external_id}/revocations"
        if "comments" not in reason or reason["comments"] == '':
            comments = "revoked via API"
        crl_reason = CRLReason.unspecified
        if "crl_reason" in reason:
            crl_reason = CRLReason[reason["crl_reason"]]

        data = {
            "crlReason": crl_reason,  # per RFC 5280 section 5.3.1
            "revocationComment": comments
        }
        response = self.session.post(revoke_url, json=data)
        metrics.send("entrust_revoke_certificate", "counter", 1)
        return handle_response(response)

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def deactivate_certificate(self, certificate):
        """Deactivates an Entrust certificate, as long as it is still active, and not already deactivated. """
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "external_id": f"{certificate.external_id}"
        }

        # backwards compatible change to protect this endpoint from being used in production
        for option in self.options:
            if option.get("name") == "staging_account" and option.get("value") is True:
                raise Exception("This issuer is not configured to deactivate certificates.")

        # Let's first check the status of the certificate
        base_url = current_app.config.get("ENTRUST_URL")
        status_url = f"{base_url}/certificates/{certificate.external_id}"
        response = self.session.get(status_url)

        try:
            data = handle_response(response)
        except (ValueError, Exception):
            # if the certificate cannot be found, there is no need to deactivate it
            log_data['message'] = "No certificate found for the ID"
            current_app.logger.info(log_data)
            return 200

        if data and data['status'].lower() == 'active':
            deactivate_url = f"{base_url}/certificates/{certificate.external_id}/deactivations"
            response = self.session.post(deactivate_url)
            metrics.send("entrust_deactivate_certificate", "counter", 1)
            return handle_response(response)
        else:
            # the certificate is no longer valid, or doesn't exist and cannot be deactivated
            return 200

    @staticmethod
    def create_authority(options):
        """Create an authority.
        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        entrust_root = current_app.config.get("ENTRUST_ROOT")
        entrust_issuing = current_app.config.get("ENTRUST_ISSUING")
        name = "entrust_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        current_app.logger.info(f"Creating Auth: {options} {entrust_issuing}")
        # body, chain, role
        return entrust_root, "", [role]

    def get_ordered_certificate(self, order_id):
        raise NotImplementedError("Not implemented\n", self, order_id)

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError("Not implemented\n", self, pending_cert, **kwargs)


class EntrustSourcePlugin(SourcePlugin):
    title = "Entrust"
    slug = "entrust-source"
    description = "Enables the collection of certificates"
    version = entrust.VERSION

    author = "sirferl"
    author_url = "https://github.com/sirferl/lemur"

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        required_vars = [
            "ENTRUST_API_USER",
            "ENTRUST_API_PASS",
            "ENTRUST_URL",
            "ENTRUST_ROOT",
            "ENTRUST_NAME",
            "ENTRUST_EMAIL",
            "ENTRUST_PHONE",
        ]
        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        cert_file = current_app.config.get("ENTRUST_API_CERT", None)
        key_file = current_app.config.get("ENTRUST_API_KEY", None)
        user = current_app.config.get("ENTRUST_API_USER")
        password = current_app.config.get("ENTRUST_API_PASS")
        if cert_file and key_file:
            # API key can be used with Client TLS certificate
            self.session.cert = (cert_file, key_file)
        self.session.auth = (user, password)
        self.session.hooks = dict(response=log_status_code)

        # max_retries applies only to failed DNS lookups, socket connections and connection timeouts,
        # never to requests where data has made it to the server.
        # we Retry we also covers HTTP status code 500, 502, 503, 504
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        super().__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        """ Fetch all Entrust certificates """
        base_url = current_app.config.get("ENTRUST_URL")
        host = base_url.replace('/enterprise/v2', '')

        get_url = f"{base_url}/certificates"
        certs = []
        processed_certs = 0
        offset = 0
        while True:
            response = self.session.get(get_url,
                 params={
                     "status": "ACTIVE",
                     "isThirdParty": "false",
                     "fields": "uri,dn",
                     "offset": offset
                 }
            )
            try:
                data = json.loads(response.content)
            except ValueError:
                # catch an empty jason object here
                data = {'response': 'No detailed message'}
            status_code = response.status_code
            if status_code > 399:
                raise Exception(f"ENTRUST error: {status_code}\n{data['errors']}")
            for c in data["certificates"]:
                download_url = "{}{}".format(
                    host, c["uri"]
                )
                cert_response = self.session.get(download_url)
                certificate = json.loads(cert_response.content)
                # normalize serial
                serial = str(int(certificate["serialNumber"], 16))
                cert = {
                    "body": certificate["endEntityCert"],
                    "serial": serial,
                    "external_id": str(certificate["trackingId"]),
                    "csr": certificate["csr"],
                    "owner": certificate["tracking"]["requesterEmail"],
                    "description": f"Imported by Lemur; Type: Entrust {certificate['certType']}\nExtended Key Usage: {certificate['eku']}"
                }
                certs.append(cert)
                processed_certs += 1
            if data["summary"]["limit"] * offset >= data["summary"]["total"]:
                break
            else:
                offset += 1
        current_app.logger.info(f"Retrieved {processed_certs} certificates")
        return certs

    def get_endpoints(self, options, **kwargs):
        # There are no endpoints in ENTRUST
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)
