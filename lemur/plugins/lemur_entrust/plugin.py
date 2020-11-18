import arrow
import requests
import json
import sys
from flask import current_app
from retrying import retry

from lemur.plugins import lemur_entrust as entrust
from lemur.plugins.bases import IssuerPlugin, SourcePlugin
from lemur.extensions import metrics
from lemur.common.utils import validate_conf


def log_status_code(r, *args, **kwargs):
    """
    Is a request hook that logs all status codes to the ENTRUST api.

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


def process_options(options, client_id):
    """
    Processes and maps the incoming issuer options to fields/options that
    Entrust understands

    :param options:
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

    data = {
        "signingAlg": "SHA-2",
        "eku": "SERVER_AND_CLIENT_AUTH",
        "certType": product_type,
        "certExpiryDate": validity_end,
        # "keyType": "RSA", Entrust complaining about this parameter
        "tracking": tracking_data,
        "org": options.get("organization"),
        "clientId": client_id
    }
    return data


def get_client_id(my_response, organization):
    """
    Helper function for parsing responses from the Entrust API.
    :param content:
    :return: :raise Exception:
    """
    try:
        d = json.loads(my_response.content)
    except ValueError:
        # catch an empty json object here
        d = {'response': 'No detailed message'}

    found = False
    for y in d["organizations"]:
        if y["name"] == organization:
            found = True
            client_id = y["clientId"]
    if found:
        return client_id
    else:
        raise Exception(f"Error on Organization - Use on of the List: {d['organizations']}")


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

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        required_vars = [
            "ENTRUST_API_CERT",
            "ENTRUST_API_KEY",
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
        cert_file = current_app.config.get("ENTRUST_API_CERT")
        key_file = current_app.config.get("ENTRUST_API_KEY")
        user = current_app.config.get("ENTRUST_API_USER")
        password = current_app.config.get("ENTRUST_API_PASS")
        self.session.cert = (cert_file, key_file)
        self.session.auth = (user, password)
        self.session.hooks = dict(response=log_status_code)
        # self.session.config['keep_alive'] = False
        super(EntrustIssuerPlugin, self).__init__(*args, **kwargs)

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

        # firstly we need the organization ID
        url = current_app.config.get("ENTRUST_URL") + "/organizations"
        try:
            response = self.session.get(url, timeout=(15, 40))
        except requests.exceptions.Timeout:
            raise Exception("Timeout for Getting Organizations")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error for Getting Organization {e}")

        client_id = get_client_id(response, issuer_options.get("organization"))
        log_data = {
            "function": f"{__name__}.{sys._getframe().f_code.co_name}",
            "message": f"Organization id: {client_id}"
        }
        current_app.logger.info(log_data)

        url = current_app.config.get("ENTRUST_URL") + "/certificates"

        data = process_options(issuer_options, client_id)
        data["csr"] = csr

        response_dict = order_and_download_certificate(self.session, url, data)

        external_id = response_dict['trackingId']
        cert = response_dict['endEntityCert']
        if len(response_dict['chainCerts']) < 2:
            # certificate signed by CA directly, no ICA included in the chain
            chain = None
        else:
            chain = response_dict['chainCerts'][1]

        log_data["message"] = "Received Chain"
        log_data["options"] = f"chain: {chain}"
        current_app.logger.info(log_data)

        return cert, chain, external_id

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def revoke_certificate(self, certificate, comments):
        """Revoke an Entrust certificate."""
        base_url = current_app.config.get("ENTRUST_URL")

        # make certificate revoke request
        revoke_url = f"{base_url}/certificates/{certificate.external_id}/revocations"
        if not comments or comments == '':
            comments = "revoked via API"
        data = {
            "crlReason": "superseded",  # enum (keyCompromise, affiliationChanged, superseded, cessationOfOperation)
            "revocationComment": comments
        }
        response = self.session.post(revoke_url, json=data)
        metrics.send("entrust_revoke_certificate", "counter", 1)
        return handle_response(response)

    @retry(stop_max_attempt_number=3, wait_fixed=1000)
    def deactivate_certificate(self, certificate):
        """Deactivates an Entrust certificate."""
        base_url = current_app.config.get("ENTRUST_URL")
        deactivate_url = f"{base_url}/certificates/{certificate.external_id}/deactivations"
        response = self.session.post(deactivate_url)
        metrics.send("entrust_deactivate_certificate", "counter", 1)
        return handle_response(response)

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
        role = {"username": "", "password": "", "name": "entrust"}
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

    def get_certificates(self, options, **kwargs):
        # Not needed for ENTRUST
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)

    def get_endpoints(self, options, **kwargs):
        # There are no endpoints in ENTRUST
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)
