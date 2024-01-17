import re
import unicodedata

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from flask import current_app
from sentry_sdk import capture_exception

from lemur.common.utils import is_selfsigned
from lemur.constants import SAN_NAMING_TEMPLATE, DEFAULT_NAMING_TEMPLATE


def text_to_slug(value, joiner="-"):
    """
    Normalize a string to a "slug" value, stripping character accents and removing non-alphanum characters.
    A series of non-alphanumeric characters is replaced with the joiner character.
    """
    if len(value) > 10_000:
        raise ValueError("Input value is too long.")

    # Strip all character accents: decompose Unicode characters and then drop combining chars.
    value = "".join(
        c for c in unicodedata.normalize("NFKD", value) if not unicodedata.combining(c)
    )

    # Replace all remaining non-alphanumeric characters with joiner string. Multiple characters get collapsed into a
    # single joiner. Except, keep 'xn--' used in IDNA domain names as is.
    value = re.sub(r"[^A-Za-z0-9.]+(?<!xn--)", joiner, value)

    # '-' in the beginning or end of string looks ugly.
    return value.strip(joiner)


def certificate_name(common_name, issuer, not_before, not_after, san, domains=[]):
    """
    Create a name for our certificate. A naming standard
    is based on a series of templates. The name includes
    useful information such as Common Name, Validation dates,
    and Issuer.

    :param common_name:
    :param not_after:
    :param issuer:
    :param not_before:
    :param san:
    :param domains:
    :rtype: str
    :return:
    """
    if san:
        t = SAN_NAMING_TEMPLATE
    else:
        t = DEFAULT_NAMING_TEMPLATE

    if common_name and common_name.strip():
        subject = common_name
    elif len(domains):
        subject = domains[0].name

    temp = t.format(
        subject=subject,
        issuer=issuer.replace(" ", ""),
        not_before=not_before.strftime("%Y%m%d"),
        not_after=not_after.strftime("%Y%m%d"),
    )

    temp = temp.replace("*", "WILDCARD")
    return text_to_slug(temp)


def signing_algorithm(cert):
    return cert.signature_hash_algorithm.name


def common_name(cert):
    """
    Attempts to get a sane common name from a given certificate.

    :param cert:
    :return: Common name or None
    """
    try:
        subject_oid = cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)
        if len(subject_oid) > 0:
            return subject_oid[0].value.strip()
        return None
    except Exception as e:
        capture_exception()
        current_app.logger.error(
            {
                "message": "Unable to get common name",
                "error": e,
                "public_key": cert.public_bytes(Encoding.PEM).decode("utf-8")
            },
            exc_info=True
        )


def organization(cert):
    """
    Attempt to get the organization name from a given certificate.
    :param cert:
    :return:
    """
    try:
        o = cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)
        if not o:
            return None

        return o[0].value.strip()
    except Exception as e:
        capture_exception()
        current_app.logger.error(f"Unable to get organization! {e}")


def organizational_unit(cert):
    """
    Attempt to get the organization unit from a given certificate.
    :param cert:
    :return:
    """
    try:
        ou = cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATIONAL_UNIT_NAME)
        if not ou:
            return None

        return ou[0].value.strip()
    except Exception as e:
        capture_exception()
        current_app.logger.error(f"Unable to get organizational unit! {e}")


def country(cert):
    """
    Attempt to get the country from a given certificate.
    :param cert:
    :return:
    """
    try:
        c = cert.subject.get_attributes_for_oid(x509.OID_COUNTRY_NAME)
        if not c:
            return None

        return c[0].value.strip()
    except Exception as e:
        capture_exception()
        current_app.logger.error(f"Unable to get country! {e}")


def state(cert):
    """
    Attempt to get the from a given certificate.
    :param cert:
    :return:
    """
    try:
        s = cert.subject.get_attributes_for_oid(x509.OID_STATE_OR_PROVINCE_NAME)
        if not s:
            return None

        return s[0].value.strip()
    except Exception as e:
        capture_exception()
        current_app.logger.error(f"Unable to get state! {e}")


def location(cert):
    """
    Attempt to get the location name from a given certificate.
    :param cert:
    :return:
    """
    try:
        loc = cert.subject.get_attributes_for_oid(x509.OID_LOCALITY_NAME)
        if not loc:
            return None

        return loc[0].value.strip()
    except Exception as e:
        capture_exception()
        current_app.logger.error(f"Unable to get location! {e}")


def domains(cert):
    """
    Attempts to get an domains listed in a certificate.
    If 'subjectAltName' extension is not available we simply
    return the common name.

    :param cert:
    :return: List of domains
    """
    domains = []
    try:
        ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
        entries = ext.value.get_values_for_type(x509.DNSName)
        for entry in entries:
            domains.append(entry)
        entries = ext.value.get_values_for_type(x509.IPAddress)
        for entry in entries:
            domains.append(str(entry))
    except x509.ExtensionNotFound:
        if current_app.config.get("LOG_SSL_SUBJ_ALT_NAME_ERRORS", True):
            capture_exception()
    except Exception as e:
        capture_exception()

    return domains


def serial(cert):
    """
    Fetch the serial number from the certificate.

    :param cert:
    :return: serial number
    """
    return cert.serial_number


def san(cert):
    """
    Determines if a given certificate is a SAN certificate.
    SAN certificates are simply certificates that cover multiple domains.

    :param cert:
    :return: Bool
    """
    if len(domains(cert)) > 1:
        return True


def is_wildcard(cert):
    """
    Determines if certificate is a wildcard certificate.

    :param cert:
    :return: Bool
    """
    d = domains(cert)
    if len(d) == 1 and d[0][0:1] == "*":
        return True

    if cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value[0:1] == "*":
        return True


def bitstrength(cert):
    """
    Calculates a certificates public key bit length.

    :param cert:
    :return: Integer
    """
    try:
        return cert.public_key().key_size
    except AttributeError:
        capture_exception()
        current_app.logger.debug("Unable to get bitstrength.")


def issuer(cert):
    """
    Gets a sane issuer slug from a given certificate, stripping non-alphanumeric characters.

    For self-signed certificates, the special value '<selfsigned>' is returned.
    If issuer cannot be determined, '<unknown>' is returned.

    :param cert: Parsed certificate object
    :return: Issuer slug
    """
    # If certificate is self-signed, we return a special value -- there really is no distinct "issuer" for it
    if is_selfsigned(cert):
        return "<selfsigned>"

    # Try Common Name or fall back to Organization name
    attrs = cert.issuer.get_attributes_for_oid(
        x509.OID_COMMON_NAME
    ) or cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)
    if not attrs:
        current_app.logger.error(
            f"Unable to get issuer! Cert serial {cert.serial_number:x}"
        )
        return "<unknown>"

    return text_to_slug(attrs[0].value, "")


def not_before(cert):
    """
    Gets the naive datetime of the certificates 'not_before' field.
    This field denotes the first date in time which the given certificate
    is valid.

    :param cert:
    :return: Datetime
    """
    return cert.not_valid_before


def not_after(cert):
    """
    Gets the naive datetime of the certificates 'not_after' field.
    This field denotes the last date in time which the given certificate
    is valid.

    :return: Datetime
    """
    return cert.not_valid_after
