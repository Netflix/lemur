"""
.. module: lemur.plugins.lemur_ejbca.plugin
    :platform: Unix

.. moduleauthor:: Selwyn Oh <selwyn.oh@primekey.com>
"""
import requests
import json
from cryptography import x509
from flask import current_app
from zeep import Client
from zeep.transports import Transport
import zeep
import re
import random
from cryptography.hazmat.backends import default_backend
from OpenSSL.crypto import load_certificate_request, load_certificate, dump_certificate_request, FILETYPE_PEM
from lemur.authorities.service import get as get_authority

from lemur.common.utils import get_psuedo_random_string
from lemur.extensions import metrics, sentry
from lemur.plugins import lemur_ejbca as ejbca 
from lemur.plugins.bases import IssuerPlugin, SourcePlugin
from lemur.plugins.lemur_ejbca.adapter import HttpsAdapter
from ipaddress import IPv4Address


def log_status_code(r, *args, **kwargs):
    """
    Is a request hook that logs all status codes to the ejbca api.

    :param r:
    :param args:
    :param kwargs:
    :return:
    """
    metrics.send("ejbca_status_code_{}".format(r.status_code), "counter", 1)


def get_additional_names(options):
    """
    Return a list of strings to be added to a SAN certificates.

    :param options:
    :return:
    """
    names = []
    # add SANs if present
    if options.get("extensions"):
        for san in options["extensions"]["sub_alt_names"]:
            if isinstance(san, x509.DNSName):
                names.append(san.value)
    return names


def get_subject_dn_string(dn_list):
    it = 0
    dn_len = len(dn_list)
    concat_dn = ""
    for kv in dn_list:
        it += 1
        concat_dn += kv[0].decode("utf-8") + "=" + kv[1].decode("utf-8")
        if it < dn_len:
            concat_dn += ","

    return concat_dn


def handle_response(response):
        """
        Handle the EJBCA API response and any errors it might have experienced.
        :param response:
        :return:
        """

        if response.status_code > 399:
            raise Exception(response.json()["error_message"])

        return response.json()


def get_subjectaltname_string(csr_pem):

    subject_alt_name = ""
    
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())

        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = san.value.get_values_for_type(x509.DNSName)
        san_ip_addrs = san.value.get_values_for_type(x509.IPAddress)
        san_uri = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        san_rfc822 = san.value.get_values_for_type(x509.RFC822Name)
        san_rid = san.value.get_values_for_type(x509.RegisteredID)
        # print(san_dns_names)
        # print(san_ip_addrs)
        # print(san_uri)
        # print(san_rfc822)
        # print(san_rid)

        cnt = 0

        for dns_val in san_dns_names:
            if cnt > 0:
                subject_alt_name += ","
            subject_alt_name += "dNSName=" + dns_val
            cnt += 1
        for ip_val in san_ip_addrs:
            if isinstance(ip_val,IPv4Address):
                if cnt > 0:
                    subject_alt_name += ","
                subject_alt_name += "iPAddress=" + ip_val.compressed
                cnt += 1
        for uri_val in san_uri:
            if cnt > 0:
                subject_alt_name += ","
            subject_alt_name += "uniformResourceIdentifier=" + uri_val
            cnt += 1
        for rfc822_val in san_rfc822:
            if cnt > 0:
                subject_alt_name += ","
            subject_alt_name += "rfc822Name=" + rfc822_val
            cnt += 1
        for oid_val in san_rid:
            if cnt > 0:
                subject_alt_name += ","
            subject_alt_name += "registeredID=" + oid_val.dotted_string

    except x509.ExtensionNotFound:
        return None

    return subject_alt_name


class EJBCAIssuerPlugin(IssuerPlugin):
    title = "EJBCA"
    slug = "ejbca-issuer"
    description = "Enables the creation of certificates via EJBCA."
    version = ejbca.VERSION

    author = "Selwyn Oh"
    author_url = "https://www.primekey.com"

    options = [
        {
            "name": "certificateProfile",
            "type": "str",
            "default": "",
            "helpMessage": "Certificate Profile",
        },
        {
            "name": "endEntityProfile",
            "type": "str",
            "default": "",
            "helpMessage": "End Entity Profile",
        },
        {
            "name": "issuer_ca",
            "type": "str",
            "default": "",
            "helpMessage": "Issuer CA Name",
        },
        {
            "name": "certificate",
            "type": "textarea",
            "default": "",
            "validation": "/^-----BEGIN CERTIFICATE-----/",
            "helpMessage": "CA Certificate",
        },
        {
            "name": "chain",
            "type": "textarea",
            "default": "",
            "validation": "/^-----BEGIN CERTIFICATE-----/",
            "helpMessage": "Certificate Chain",
        },
    ]

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        self.session.cert = current_app.config.get("EJBCA_PEM_PATH")
        self.session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
        self.session.hooks = dict(response=log_status_code)
        super(EJBCAIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates a Verisign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        authority_obj = issuer_options.get("authority")

        authority_options = {}

        for option in json.loads(authority_obj.options):
            authority_options[option["name"]] = option.get("value")
        certificate_profile = authority_options.get("certificateProfile")
        end_entity_profile = authority_options.get("endEntityProfile")
        issuer_ca = authority_options.get("issuer_ca")

        authority_const = issuer_options.get("authority").name.upper()

        session = requests.Session()
        session.mount('https://', HttpsAdapter())
        session.cert = current_app.config.get("EJBCA_PEM_PATH_{0}".format(authority_const), current_app.config.get("EJBCA_PEM_PATH"))
        session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
        session.hooks = dict(response=log_status_code)

        transport = Transport(session=session)

        url = current_app.config.get("EJBCA_URL") + "/ejbca/ejbcaws/ejbcaws?wsdl"

        client = Client(url, transport=transport)

        #csr_x509 = x509.load_pem_x509_csr(csr.encode("utf-8"), default_backend())
        csr_x509 = load_certificate_request(FILETYPE_PEM, csr)
        # get SubjectDN string from CSR
        subject_dn = get_subject_dn_string(csr_x509.get_subject().get_components())
        # print("*****DN:" + subject_dn)

        subject_alt_names = get_subjectaltname_string(csr)

        end_entity_username = issuer_options.get("name")
        if end_entity_username is None:
            end_entity_username = "testing"

        # compose userDataVOWS object
        user_data_vows_type = client.get_type('ns0:userDataVOWS')
        user_data_vows = user_data_vows_type(username=end_entity_username,password='foo123',clearPwd='false',subjectDN=subject_dn,caName=issuer_ca,certificateProfileName=certificate_profile,endEntityProfileName=end_entity_profile,sendNotification='false',keyRecoverable='false',status='10',tokenType='USERGENERATED',email=None,subjectAltName=subject_alt_names)

        try:
            response = client.service.editUser(user_data_vows)

            csr_b64 = dump_certificate_request(FILETYPE_PEM, csr_x509)
            csr_b64 = csr_b64.decode()

            request_data = {
                'arg0': end_entity_username,
                'arg1': 'foo123',
                'arg2': csr_b64,
                'arg3': None,
                'arg4': 'CERTIFICATE'
            }

            try:
                response = client.service.pkcs10Request(**request_data)

                print(response)
                print(response.data)

                cert_data_str = response.data.decode("utf-8")

                print("CERT DATA")
                print(cert_data_str)
                #cert_data = base64.b64decode(cert_data_str).decode("utf-8")
                cert_data_str.replace('\\n', '\n')
                print("decoded:")
                print(cert_data_str)
                
                # External ID required for revocation
                # Generate a random ID
                rand_external_id = random.randrange(10**11, 10**12)
                external_id = str(rand_external_id)
                #reconstruct certificate from json array
                pem = "-----BEGIN CERTIFICATE-----\n"
                pem += cert_data_str
                 
                pem += "\n-----END CERTIFICATE-----"

                authority = issuer_options.get("authority").name.upper()
                chain = current_app.config.get("EJBCA_INTERMEDIATE_{0}".format(authority), current_app.config.get("EJBCA_INTERMEDIATE"))
                return pem, chain, external_id

            except zeep.exceptions.Fault as fault:
                raise Exception(fault.message)              

        except zeep.exceptions.Fault as fault:
            parsed_fault_detail = client.wsdl.types.deserialize(fault.detail[0])
            print(len(fault.detail))
            print(parsed_fault_detail)
            
            if hasattr(parsed_fault_detail, 'requestId'):
                print("has details:" + str(parsed_fault_detail.requestId))
                request_id = parsed_fault_detail.requestId
                return None, None, request_id

            else:
                raise Exception(fault.message)

    #Resolve Pending EJBCA Certificate
    def get_ordered_certificate(self, pending_cert):

        rejected = False
        expired = False
        try:

            authority_const = issuer_options.get("authority").name.upper()

            session = requests.Session()
            session.mount('https://', HttpsAdapter())
            session.cert = current_app.config.get("EJBCA_PEM_PATH_{0}".format(authority_const))
            session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
            session.hooks = dict(response=log_status_code)

            transport = Transport(session=session)
            url = current_app.config.get("EJBCA_URL") + "/ejbca/ejbcaws/ejbcaws?wsdl"

            client = Client(url, transport=transport)

            csr_x509 = load_certificate_request(FILETYPE_PEM, pending_cert.csr)
            # get SubjectDN string from CSR
            subject_dn = get_subject_dn_string(csr_x509.get_subject().get_components())
            print("get_ordered_certificate: *****DN:" + subject_dn)

            end_entity_username = pending_cert.name
            if end_entity_username is None:
                end_entity_username = "testing"

            # Strip -[digit]+ from pending cert name to obtain end entity username
            end_entity_username = re.sub('-\d+$', '', end_entity_username)

            response = client.service.getRemainingNumberOfApprovals(pending_cert.external_id)

            num_remaining = response

            if num_remaining == -1:
                print("Rejected!")
                rejected = True
                return False
            elif num_remaining > 0:
                print(f"get_ordered_certificate: Approvals Remaining {str(num_remaining)}")
                return False
            elif num_remaining == 0:
                #ready to issue cert
                csr_b64 = dump_certificate_request(FILETYPE_PEM, csr_x509)
                csr_b64 = csr_b64.decode()
                request_data = {
                    'arg0':end_entity_username,
                    'arg1':'foo123',
                    'arg2':csr_b64,
                    'arg3':None,
                    'arg4':'CERTIFICATE'
                }

                try:
                    response = client.service.pkcs10Request(**request_data)

                    cert_data_str = response.data.decode("utf-8")

                    print("CERT DATA")
                    print(cert_data_str)
                    #cert_data = base64.b64decode(cert_data_str).decode("utf-8")
                    cert_data_str.replace('\\n', '\n')
                    print("decoded:")
                    print(cert_data_str)
                    external_id = None
                    #reconstruct certificate from json array
                    pem = "-----BEGIN CERTIFICATE-----\n"
                    pem += cert_data_str
                     
                    pem += "\n-----END CERTIFICATE-----"

                    authority = get_authority(pending_cert.authority_id)
                    authority_name = authority.name.upper()
                    #authority = issuer_options.get("authority").name.upper()
                    chain = current_app.config.get("EJBCA_INTERMEDIATE_{0}".format(authority_name), current_app.config.get("EJBCA_INTERMEDIATE"))
                    
                    cert = {
                        "body": pem,
                        "chain": "\n".join(str(chain).splitlines()),
                        "external_id": str(pending_cert.external_id),
                        "authority_id": str(pending_cert.authority_id),
                    }
                    #certs.append({"cert": cert, "pending_cert": entry["pending_cert"]})
                    return cert

                except zeep.exceptions.Fault as fault:
                    sentry.captureException()
                    metrics.send(
                        "get_ordered_certificate_pending_creation_error", "counter", 1
                    )
                    current_app.logger.error(
                        f"get_ordered_certificate: Unable to resolve EJBCA pending cert: {pending_cert}", exc_info=True
                    )

                    return False
        except zeep.exceptions.Fault as fault:
                
            strdet = fault.detail[0]
            m = re.search('^\{.*\}(.*)$', strdet.tag)
            exceptname = m.group(1)
            if (exceptname == "ApprovalRequestExpiredException"):
                expired = True
            return False
        return False

    # Resolve Pending EJBCA Certificates
    def get_ordered_certificates(self, pending_certs):
        pending = []
        certs = []
        for pending_cert in pending_certs:
            rejected = False
            expired = False
            try:

                authority = get_authority(pending_cert.authority_id)
                authority_name = authority.name.upper()
                
                print("AUTHORITYNAME**** " + authority_name)

                session = requests.Session()
                session.mount('https://', HttpsAdapter())
                session.cert = current_app.config.get("EJBCA_PEM_PATH_{0}".format(authority_name))
                session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
                session.hooks = dict(response=log_status_code)
                transport = Transport(session=session)
                url = current_app.config.get("EJBCA_URL") + "/ejbca/ejbcaws/ejbcaws?wsdl"

                client = Client(url, transport=transport)

                csr_x509 = load_certificate_request(FILETYPE_PEM, pending_cert.csr)
                # get SubjectDN string from CSR
                subject_dn = get_subject_dn_string(csr_x509.get_subject().get_components())
                print("*****DN:" + subject_dn)


                end_entity_username = pending_cert.name
                if end_entity_username is None:
                    end_entity_username = "testing"

                # Strip -[digit]+ from pending cert name to obtain end entity username
                end_entity_username = re.sub('-\d+$', '', end_entity_username)

                response = client.service.getRemainingNumberOfApprovals(pending_cert.external_id)

                num_remaining = response
                current_app.logger.debug(
                    f"Remaining check: {str(num_remaining)}"
                )

                if num_remaining == -1:
                    print("Rejected!")
                    rejected = True
                    certs.append(
                        {"cert": False, "pending_cert": pending_cert, "last_error": "Request was rejected", "rejected" : rejected, "expired" : expired}
                    )
                elif num_remaining > 0:
                    current_app.logger.debug(
                        f"Remaining Approvals: {num_remaining}"
                    )
                    print("Approvals Remaining")
                    remain_message = "Remaining approvals: " + str(num_remaining)
                    certs.append(
                        {"cert": False, "pending_cert": pending_cert, "last_error": remain_message, "rejected" : rejected, "expired" : expired}
                    )
                elif num_remaining == 0:
                    #ready to issue cert
                    csr_b64 = dump_certificate_request(FILETYPE_PEM, csr_x509)
                    csr_b64 = csr_b64.decode()

                    request_data = {
                        'arg0':end_entity_username,
                        'arg1':'foo123',
                        'arg2':csr_b64,
                        'arg3':None,
                        'arg4':'CERTIFICATE'
                    }

                    try:
                        response = client.service.pkcs10Request(**request_data)

                        print(response)
                        print(response.data)

                        cert_data_str = response.data.decode("utf-8")

                        print("CERT DATA")
                        print(cert_data_str)
                        #cert_data = base64.b64decode(cert_data_str).decode("utf-8")
                        cert_data_str.replace('\\n', '\n')
                        print("decoded:")
                        print(cert_data_str)
                        external_id = None
                        #reconstruct certificate from json array
                        pem = "-----BEGIN CERTIFICATE-----\n"
                        pem += cert_data_str
                         
                        pem += "\n-----END CERTIFICATE-----"

                        #authority = get_authority(pending_cert.authority_id)
                        #authority_name = authority.name.upper()
                        chain = current_app.config.get("EJBCA_INTERMEDIATE_{0}".format(authority_name), current_app.config.get("EJBCA_INTERMEDIATE"))
                        
                        cert = {
                            "body": pem,
                            "chain": "\n".join(str(chain).splitlines()),
                            "external_id": str(pending_cert.external_id),
                            "authority_id": str(pending_cert.authority_id),
                        }
                        certs.append({"cert": cert, "pending_cert": pending_cert})

                    except zeep.exceptions.Fault as fault:
                        sentry.captureException()
                        metrics.send(
                            "get_ordered_certificates_pending_creation_error", "counter", 1
                        )
                        current_app.logger.error(
                            f"Unable to resolve EJBCA pending cert: {pending_cert}", exc_info=True
                        )

                        certs.append(
                            {"cert": False, "pending_cert": pending_cert, "last_error": fault.message, "rejected" : rejected, "expired" : expired}
                        )

            except zeep.exceptions.Fault as fault:
                strdet = fault.detail[0]
                m = re.search('^\{.*\}(.*)$', strdet.tag)
                exceptname = m.group(1)
                if (exceptname == "ApprovalRequestExpiredException"):
                    expired = True
                certs.append(
                    {"cert": False, "pending_cert": pending_cert, "last_error": fault.message, "rejected" : rejected, "expired" : expired}
                )

        return certs

    def revoke_certificate(self, certificate, comments):
        """Revoke an EJBCA certificate."""
        base_url = current_app.config.get("EJBCA_URL")

        authority = get_authority(certificate.authority_id)
        authority_const = authority.name.upper()

        cert_body = certificate.body

        x509 = load_certificate(FILETYPE_PEM, cert_body)

        issuer = x509.get_issuer()
        issuer_dn = get_subject_dn_string(issuer.get_components())

        # create certificate revocation request
        hex_serial = hex(int(certificate.serial))[2:]
        
        cert_serial_hex = str(hex_serial)
        
        create_url = "{0}/ejbca/ejbca-rest-api/v1/certificate/{1}/{2}/revoke".format(
            base_url, issuer_dn, cert_serial_hex
        )
        
        print(create_url)

        session = requests.Session()
        session.mount('https://', HttpsAdapter())
        session.cert = current_app.config.get("EJBCA_PEM_PATH_{0}".format(authority_const))
        session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
        session.hooks = dict(response=log_status_code)

        metrics.send("ejbca_revoke_certificate", "counter", 1)
        response = session.put(create_url, params={'reason': 'CERTIFICATE_HOLD'})
        print(response)
        return handle_response(response)

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "ejbca"}

        plugin_options = options.get("plugin", {}).get("plugin_options")
        if not plugin_options:
            error = "Invalid options for lemur_ejbca plugin: {}".format(options)
            current_app.logger.error(error)
            raise InvalidConfiguration(error)
        # Define static auth_root based off configuration variable by default. However, if user has passed a
        # certificate, use this certificate as the root.
        ejbca_root = current_app.config.get("EJBCA_ROOT")
        chain = ""

        for option in plugin_options:
            if option.get("name") == "certificate":
                ejbca_root = option.get("value")
            elif option.get("name") == "chain":
                chain = option.get("chain")
        return ejbca_root, chain, [role]


class EJBCASourcePlugin(SourcePlugin):
    title = "EJBCA Source"
    slug = "ejbca-source"
    description = (
        "Allows for the polling of issued certificates from EJBCA."
    )
    version = ejbca.VERSION

    author = "Selwyn Oh"
    author_url = "https://www.primekey.com"

    additional_options = [
        {
            "name": "issuerdn",
            "type": "str",
            "validation": "^.+$",
            "helpMessage": "Issuer DN",
            "default": "Lemur",
        },
        {
            "name": "source_const",
            "type": "str",
            "validation": "^.+$",
            "helpMessage": "Source Constant",
            "default": "",
        },
    ]

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        self.session.cert = current_app.config.get("EJBCA_PEM_PATH")
        self.session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
        self.session.hooks = dict(response=log_status_code)
        super(EJBCASourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        
        certs = []
        issuer_dn = self.get_option("issuerdn", options)
        source_const = self.get_option("source_const", options)
        if source_const is not None:
            source_const = source_const.upper()

        # print("SOURCE**** " +str(source_const))
        session = requests.Session()
        session.mount('https://', HttpsAdapter())
        session.cert = current_app.config.get("EJBCA_PEM_PATH_{0}".format(source_const), current_app.config.get("EJBCA_PEM_PATH"))
        session.verify = current_app.config.get("EJBCA_TRUSTSTORE")
        session.hooks = dict(response=log_status_code)

        source_expire_days = current_app.config.get("EJBCA_SOURCE_EXPIRE_DAYS", 7300)
        source_max_results = current_app.config.get("EJBCA_SOURCE_MAX_RESULTS", 100000)

        request_data = {
           'arg0': source_expire_days,
           'arg1': issuer_dn,
           'arg2': source_max_results,
        }

        transport = Transport(session=session)
        url = current_app.config.get("EJBCA_URL") + "/ejbca/ejbcaws/ejbcaws?wsdl"

        client = Client(url, transport=transport)

        response = client.service.getCertificatesByExpirationTimeAndIssuer(**request_data)
        num_certs = len(response)

        for x in range(num_certs):
            encoded_cert = response[x].certificateData
            
            decoded_cert = encoded_cert.decode('utf-8')
            pem = "-----BEGIN CERTIFICATE-----\n"
            pem += decoded_cert
            pem += "\n-----END CERTIFICATE-----"

            x509 = load_certificate(FILETYPE_PEM, pem)
            # get SubjectDN string from CSR
            serial = x509.get_serial_number()
            # External ID required for revocation
            # Generate a random ID
            rand_external_id = random.randrange(10**11, 10**12)
            external_id = str(rand_external_id)

            chain = '{}\n{}'.format(current_app.config.get('EJBCA_INTERMEDIATE', '').strip(),
                                    current_app.config.get('EJBCA_ROOT', '').strip())
            cert = {
                "body": "\n".join(str(pem).splitlines()),
                "serial": serial,
                "external_id": external_id,
                "chain": chain,
            }
            certs.append(cert)

        return certs
