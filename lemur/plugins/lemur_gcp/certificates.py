from cryptography import x509
from flask import current_app
from google.cloud.compute_v1.services import ssl_certificates, region_ssl_certificates

from lemur.common.defaults import common_name, text_to_slug
from lemur.common.utils import parse_certificate, split_pem
from lemur.plugins.lemur_gcp import utils


def get_name(body):
    """
    We need to change the name of the certificate that we are uploading to comply with GCP naming standards.
    The cert name will follow the convention "{cn}-{authority}-{serial}". This is guaranteed to be unique
    across CAs and complies with naming restrictions from the GCP API. If the combined authority and serial
    number of certificate is longer than 63 characters, an exception is raised. This assumes the CA conforms
    to https://www.rfc-editor.org/rfc/rfc3280#section-4.1.2.2 and the serial number is a positive integer.
    """
    cert = parse_certificate(body)
    authority = modify_for_gcp(get_issuer(cert))
    serial = modify_for_gcp(hex(cert.serial_number))
    suffix = f"-{authority}-{serial}"
    if len(suffix) > 63:
        raise Exception(f"Could not create certificate due to naming restrictions: {cert.serial_number}")
    cn = modify_for_gcp(common_name(cert))
    available_chars = 63 - len(suffix)
    cn = cn[:available_chars]
    cert_name = f"{cn}{suffix}"
    return cert_name


def get_issuer(cert):
    authority = cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)
    if not authority:
        current_app.logger.error(
            "Unable to get issuer! Cert serial {:x}".format(cert.serial_number)
        )
        return "<unknown>"
    return text_to_slug(authority[0].value, "")


def modify_for_gcp(name):
    # Modify the name to comply with GCP naming convention
    gcp_name = name.replace('.', '-')
    gcp_name = gcp_name.replace("*", "star")
    gcp_name = gcp_name.lower()
    gcp_name = gcp_name.rstrip('.*-')
    return gcp_name


def full_ca(body, cert_chain):
    # in GCP you need to assemble the cert body and the cert chain in the same parameter
    return f"{body}\n{cert_chain}"


def insert_certificate(project_id, ssl_certificate_body, credentials, region=None):
    if not region:
        ssl_certificates.SslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body
        )
    else:
        region_ssl_certificates.RegionSslCertificatesClient(credentials=credentials).insert(
            project=project_id, ssl_certificate_resource=ssl_certificate_body, region=region
        )


def fetch_all(project_id, credentials):
    client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    certs = []
    for cert_meta in client.list(project=project_id):
        try:
            if cert_meta.type_ != "SELF_MANAGED":
                continue
            cert = parse_certificate_meta(cert_meta)
            if cert:
                certs.append(cert)
        except Exception as e:
            current_app.logger.error(
                f"Issue with fetching certificate {cert_meta.name} from GCP. Action failed with the following "
                f"log: {e}",
                exc_info=True,
            )
            raise e
    return certs


def fetch_by_name(project_id, credentials, certificate_name):
    client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    cert_meta = client.get(project=project_id, ssl_certificate=certificate_name)
    if cert_meta:
        cert = parse_certificate_meta(cert_meta)
        if cert:
            return cert
    return None


def parse_certificate_meta(certificate_meta):
    """
    Returns a body and a chain.
    :param certificate_meta:
    """
    chain = []
    # Skip CSR if it's part of the certificate returned by the GCP API.
    for cert in split_pem(certificate_meta.certificate):
        if "-----BEGIN CERTIFICATE-----" in cert:
            chain.append(cert)
    if not chain:
        return None
    return dict(
        body=chain[0],
        chain="\n".join(chain[1:]),
        name=certificate_meta.name,
    )


def get_self_link(project, name):
    return f"https://www.googleapis.com/compute/v1/projects/{project}/global/sslCertificates/{name}"


def find_cert(project_id, credentials, body, cert_self_links):
    """
    Fetches the certificate bodies for each self_link and returns the first match by body.
    :param project_id:
    :param credentials:
    :param body:
    :param cert_self_links:
    :return: The self link with a matching body, if it exists.
    """
    client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    for self_link in cert_self_links:
        name = utils.get_name_from_self_link(self_link)
        cert_meta = client.get(project=project_id, ssl_certificate=name)
        parsed_cert = parse_certificate_meta(cert_meta)
        # The uploaded certificate may be invalid since GCP does not validate the body.
        if not parsed_cert:
            raise Exception(f"could not parse metadata for certificate {name}")
        if parsed_cert["body"] == body:
            return self_link
    return None


def calc_diff(certs, new_cert, old_cert):
    """
    Produces a list of certificate self-links where new_cert is added and old_cert is removed, if it exists.
    The given certs are assumed to be unique and this is a no-op if new_cert and old_cert are the same.
    If new_cert already exists in certs, it will not be added.
    If old_cert already does not exist in certs, this is a no-op.
    certs[0] is assumed to be the default cert and is never modified.
    :param certs:
    :param new_cert:
    :param old_cert:
    :return:
    """
    # Shallow copy the list of self-links (strings)
    result = list(certs)
    if len(certs) != len(set(result)):
        raise Exception(f"expected given certs {certs} to be unique but were not")
    if new_cert == old_cert:
        return result
    elif len(result) == 0:
        return result
    elif certs[0] == old_cert:
        raise Exception("cannot use SNI rotation when old_cert is the default")
    old_cert_idx = -1
    for idx, self_link in enumerate(result):
        if self_link == old_cert:
            old_cert_idx = idx
            break
    if new_cert not in result:
        if old_cert_idx > 0:
            result[old_cert_idx] = new_cert
        else:
            result.append(new_cert)
    # Old cert can only exist at idx > 0 and removing an SNI cert is safe to do.
    if old_cert in result:
        result.remove(old_cert)
    return result
