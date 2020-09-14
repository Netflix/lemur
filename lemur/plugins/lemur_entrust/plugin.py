from lemur.plugins.bases import IssuerPlugin, SourcePlugin
import arrow
import requests
import json
from lemur.plugins import lemur_entrust as ENTRUST
from flask import current_app
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
    metrics.send("ENTRUST_status_code_{}".format(r.status_code), "counter", 1)


def process_options(options):
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
    product_type = current_app.config.get("ENTRUST_PRODUCT_{0}".format(authority), "STANDARD_SSL")
    expiry_date = arrow.utcnow().shift(years=1, days=+10).format('YYYY-MM-DD')

    tracking_data = {
        "requesterName": current_app.config.get("ENTRUST_NAME"),
        "requesterEmail": current_app.config.get("ENTRUST_EMAIL"),
        "requesterPhone": current_app.config.get("ENTRUST_PHONE")
    }

    data = {
        "signingAlg": "SHA-2",
        "eku": "SERVER_AND_CLIENT_AUTH",
        "certType": product_type,
        "certExpiryDate": expiry_date,
        "tracking": tracking_data
    }
    return data


class EntrustIssuerPlugin(IssuerPlugin):
    title = "ENTRUST"
    slug = "entrust-issuer"
    description = "Enables the creation of certificates by ENTRUST"
    version = ENTRUST.VERSION

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
            "ENTRUST_ISSUING",
        ]
        validate_conf(current_app, required_vars)

        self.session = requests.Session()
        cert_file_path = current_app.config.get("ENTRUST_API_CERT")
        key_file_path = current_app.config.get("ENTRUST_API_KEY")
        user = current_app.config.get("ENTRUST_API_USER")
        passw = current_app.config.get("ENTRUST_API_PASS")
        self.session.cert = (cert_file_path, key_file_path)
        self.session.auth = (user, passw)
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
        current_app.logger.info(
            "Requesting options: {0}".format(issuer_options)
        )

        url = current_app.config.get("ENTRUST_URL") + "/certificates"

        data = process_options(issuer_options)
        data["csr"] = csr
        current_req = arrow.utcnow().format('YYYY-MM-DD HH:mm:ss')
        current_app.logger.info(
            "Entrust-Request Data (id: {1})  : {0}".format(data, current_req)
        )

        try:
            response = self.session.post(url, json=data, timeout=(15, 40))
        except requests.exceptions.Timeout:
            raise Exception("Timeout Error while posting to ENTRUST (ID: {0})".format(current_req))
        except requests.exceptions.RequestException as e:
            raise Exception("Error while posting to ENTRUST (ID: {1}):  {0}".format(e, current_req))

        current_app.logger.info(
            "After Post and Errorhandling (ID: {1}) : {0}".format(response.status_code, current_req)
        )

        response_dict = json.loads(response.content)
        if response.status_code != 201:
            raise Exception("Error with ENTRUST (ID: {1}): {0}".format(response_dict['errors'], current_req))
        current_app.logger.info("Response: {0}, {1} ".format(response.status_code, response_dict))
        external_id = response_dict['trackingId']
        cert = response_dict['endEntityCert']
        chain = response_dict['chainCerts'][1]
        current_app.logger.info(
            "Received Chain: {0}".format(chain)
        )

        return cert, chain, external_id

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
        current_app.logger.info("Creating Auth: {0} {1}".format(options, entrust_issuing))
        return entrust_root, "", [role]

    def revoke_certificate(self, certificate, comments):
        raise NotImplementedError("Not implemented\n", self, certificate, comments)

    def get_ordered_certificate(self, order_id):
        raise NotImplementedError("Not implemented\n", self, order_id)

    def canceled_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError("Not implemented\n", self, pending_cert, **kwargs)


class EntrustSourcePlugin(SourcePlugin):
    title = "ENTRUST"
    slug = "entrust-source"
    description = "Enables the collecion of certificates"
    version = ENTRUST.VERSION

    author = "sirferl"
    author_url = "https://github.com/sirferl/lemur"
    options = [
        {
            "name": "dummy",
            "type": "str",
            "required": False,
            "validation": "/^[0-9]{12,12}$/",
            "helpMessage": "Just to prevent error",
        }
    ]

    def get_certificates(self, options, **kwargs):
        # Not needed for ENTRUST
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)

    def get_endpoints(self, options, **kwargs):
        # There are no endpoints in ENTRUST
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)
