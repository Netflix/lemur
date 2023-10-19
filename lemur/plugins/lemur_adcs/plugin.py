from lemur.plugins.bases import IssuerPlugin, SourcePlugin
import requests
from lemur.plugins import lemur_adcs as ADCS
from certsrv import Certsrv
from OpenSSL import crypto
from flask import current_app


class ADCSIssuerPlugin(IssuerPlugin):
    title = "ADCS"
    slug = "adcs-issuer"
    description = "Enables the creation of certificates by ADCS (Active Directory Certificate Services)"
    version = ADCS.VERSION

    author = "sirferl"
    author_url = "https://github.com/sirferl/lemur"

    def __init__(self, *args, **kwargs):
        """Initialize the issuer with the appropriate details."""
        self.session = requests.Session()
        super().__init__(*args, **kwargs)

    @staticmethod
    def create_authority(options):
        """Create an authority.
        Creates an authority, this authority is then used by Lemur to
        allow a user to specify which Certificate Authority they want
        to sign their certificate.

        :param options:
        :return:
        """
        adcs_root = current_app.config.get("ADCS_ROOT")
        adcs_issuing = current_app.config.get("ADCS_ISSUING")
        name = "adcs_" + "_".join(options['name'].split(" ")) + "_admin"
        role = {"username": "", "password": "", "name": name}
        return adcs_root, adcs_issuing, [role]

    def create_certificate(self, csr, issuer_options):
        adcs_server = current_app.config.get("ADCS_SERVER")
        adcs_user = current_app.config.get("ADCS_USER")
        adcs_pwd = current_app.config.get("ADCS_PWD")
        adcs_auth_method = current_app.config.get("ADCS_AUTH_METHOD")
        # if there is a config variable ADCS_TEMPLATE_<upper(authority.name)> take the value as Cert template
        # else default to ADCS_TEMPLATE to be compatible with former versions
        authority = issuer_options.get("authority").name.upper()
        adcs_template = current_app.config.get(f"ADCS_TEMPLATE_{authority}", current_app.config.get("ADCS_TEMPLATE"))
        ca_server = Certsrv(
            adcs_server, adcs_user, adcs_pwd, auth_method=adcs_auth_method
        )
        current_app.logger.info(f"Requesting CSR: {csr}")
        current_app.logger.info(f"Issuer options: {issuer_options}")
        cert = (
            ca_server.get_cert(csr, adcs_template, encoding="b64")
            .decode("utf-8")
            .replace("\r\n", "\n")
        )
        chain = (
            ca_server.get_ca_cert(encoding="b64").decode("utf-8").replace("\r\n", "\n")
        )
        return cert, chain, None

    def revoke_certificate(self, certificate, reason):
        raise NotImplementedError("Not implemented\n", self, certificate, reason)

    def get_ordered_certificate(self, order_id):
        raise NotImplementedError("Not implemented\n", self, order_id)

    def canceled_ordered_certificate(self, pending_cert, **kwargs):
        raise NotImplementedError("Not implemented\n", self, pending_cert, **kwargs)


class ADCSSourcePlugin(SourcePlugin):
    title = "ADCS"
    slug = "adcs-source"
    description = "Enables the collecion of certificates"
    version = ADCS.VERSION

    author = "sirferl"
    author_url = "https://github.com/sirferl/lemur"

    def get_certificates(self, options, **kwargs):
        adcs_server = current_app.config.get("ADCS_SERVER")
        adcs_user = current_app.config.get("ADCS_USER")
        adcs_pwd = current_app.config.get("ADCS_PWD")
        adcs_auth_method = current_app.config.get("ADCS_AUTH_METHOD")
        adcs_start = current_app.config.get("ADCS_START")
        adcs_stop = current_app.config.get("ADCS_STOP")
        ca_server = Certsrv(
            adcs_server, adcs_user, adcs_pwd, auth_method=adcs_auth_method
        )
        out_certlist = []
        for id in range(adcs_start, adcs_stop):
            try:
                cert = (
                    ca_server.get_existing_cert(id, encoding="b64")
                    .decode("utf-8")
                    .replace("\r\n", "\n")
                )
            except Exception as err:
                if f"{err}".find("CERTSRV_E_PROPERTY_EMPTY"):
                    # this error indicates end of certificate list(?), so we stop
                    break
                else:
                    # We do nothing in case there is no certificate returned for other reasons
                    current_app.logger.info(f"Error with id {id}: {err}")
            else:
                # we have a certificate
                pubkey = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                # loop through extensions to see if we find "TLS Web Server Authentication"
                for e_id in range(0, pubkey.get_extension_count() - 1):
                    try:
                        extension = f"{pubkey.get_extension(e_id)}"
                    except Exception:
                        extensionn = ""
                    if extension.find("TLS Web Server Authentication") != -1:
                        out_certlist.append(
                            {"name": format(pubkey.get_subject().CN), "body": cert}
                        )
                        break
        return out_certlist

    def get_endpoints(self, options, **kwargs):
        # There are no endpoints in the ADCS
        raise NotImplementedError("Not implemented\n", self, options, **kwargs)
