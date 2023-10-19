"""
.. module: lemur.common.utils
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import base64
import json
import re
import secrets
import socket
import ssl
import string

import OpenSSL
import pem
import sqlalchemy
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, pkcs7
from flask_restful.reqparse import RequestParser
from sqlalchemy import and_, func
import josepy as jose

from certbot.crypto_util import CERT_PEM_REGEX
from lemur.constants import CERTIFICATE_KEY_TYPES
from lemur.exceptions import InvalidConfiguration
from lemur.utils import Vault
from sqlalchemy.dialects.postgresql import TEXT

paginated_parser = RequestParser()

paginated_parser.add_argument("count", type=int, default=10, location="args")
paginated_parser.add_argument("page", type=int, default=1, location="args")
paginated_parser.add_argument("sortDir", type=str, dest="sort_dir", location="args")
paginated_parser.add_argument("sortBy", type=str, dest="sort_by", location="args")
paginated_parser.add_argument("filter", type=str, location="args")
paginated_parser.add_argument("owner", type=str, location="args")


def base64encode(string):
    # Performs Base64 encoding of string to string using the base64.b64encode() function
    # which encodes bytes to bytes.
    return base64.b64encode(string.encode()).decode()


def base64decode(base64_input):
    # Performs Base64 decoging of a b64 string to string using the base64.b64encode() function
    # which encodes bytes to bytes.
    return base64.b64decode(base64_input.encode()).decode()


def get_psuedo_random_string():
    """
    Create a random and strongish challenge.
    """
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "~!@#$%^&*()_+"
    challenge = ''.join(secrets.choice(chars) for x in range(24))
    return challenge


def get_random_secret(length):
    """ Similar to get_pseudo_random_string, but accepts a length parameter. """
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + "~!@#$%^&*()_+"
    return ''.join(secrets.choice(chars) for x in range(length))


def get_state_token_secret():
    return base64.b64encode(get_random_secret(32).encode('utf8'))


def parse_certificate(body):
    """
    Helper function that parses a PEM certificate.

    :param body:
    :return:
    """
    assert isinstance(body, str)

    return x509.load_pem_x509_certificate(body.encode("utf-8"), default_backend())


def parse_private_key(private_key):
    """
    Parses a PEM-format private key (RSA, DSA, ECDSA or any other supported algorithm).

    Raises ValueError for an invalid string. Raises AssertionError when passed value is not str-type.

    :param private_key: String containing PEM private key
    """
    assert isinstance(private_key, str)

    return load_pem_private_key(
        private_key.encode("utf8"), password=None, backend=default_backend()
    )


def get_key_type_from_certificate(body):
    """

    Helper function to determine key type by pasrding given PEM certificate

    :param body: PEM string
    :return: Key type string
    """
    parsed_cert = parse_certificate(body)
    if isinstance(parsed_cert.public_key(), rsa.RSAPublicKey):
        return "RSA{key_size}".format(
            key_size=parsed_cert.public_key().key_size
        )
    elif isinstance(parsed_cert.public_key(), ec.EllipticCurvePublicKey):
        return get_key_type_from_ec_curve(parsed_cert.public_key().curve.name)


def split_pem(data):
    """
    Split a string of several PEM payloads to a list of strings.

    :param data: String
    :return: List of strings
    """
    return re.split("\n(?=-----BEGIN )", data)


def parse_cert_chain(pem_chain):
    """
    Helper function to split and parse a series of PEM certificates.

    :param pem_chain: string
    :return: List of parsed certificates
    """
    if pem_chain is None:
        return []
    return [parse_certificate(cert) for cert in split_pem(pem_chain) if cert]


def parse_csr(csr):
    """
    Helper function that parses a CSR.

    :param csr:
    :return:
    """
    assert isinstance(csr, str)

    return x509.load_pem_x509_csr(csr.encode("utf-8"), default_backend())


def get_authority_key(body):
    """Returns the authority key for a given certificate in hex format"""
    parsed_cert = parse_certificate(body)
    authority_key = parsed_cert.extensions.get_extension_for_class(
        x509.AuthorityKeyIdentifier
    ).value.key_identifier
    return authority_key.hex()


def get_key_type_from_ec_curve(curve_name):
    """
    Give an EC curve name, return the matching key_type.

    :param: curve_name
    :return: key_type
    """

    _CURVE_TYPES = {
        ec.SECP192R1().name: "ECCPRIME192V1",
        ec.SECP256R1().name: "ECCPRIME256V1",
        ec.SECP224R1().name: "ECCSECP224R1",
        ec.SECP384R1().name: "ECCSECP384R1",
        ec.SECP521R1().name: "ECCSECP521R1",
        ec.SECP256K1().name: "ECCSECP256K1",
        ec.SECT163K1().name: "ECCSECT163K1",
        ec.SECT233K1().name: "ECCSECT233K1",
        ec.SECT283K1().name: "ECCSECT283K1",
        ec.SECT409K1().name: "ECCSECT409K1",
        ec.SECT571K1().name: "ECCSECT571K1",
        ec.SECT163R2().name: "ECCSECT163R2",
        ec.SECT233R1().name: "ECCSECT233R1",
        ec.SECT283R1().name: "ECCSECT283R1",
        ec.SECT409R1().name: "ECCSECT409R1",
        ec.SECT571R1().name: "ECCSECT571R2",
    }

    if curve_name in _CURVE_TYPES.keys():
        return _CURVE_TYPES[curve_name]
    else:
        return None


def generate_private_key(key_type):
    """
    Generates a new private key based on key_type.

    Valid key types: RSA2048, RSA4096', 'ECCPRIME192V1', 'ECCPRIME256V1', 'ECCSECP192R1',
        'ECCSECP224R1', 'ECCSECP256R1', 'ECCSECP384R1', 'ECCSECP521R1', 'ECCSECP256K1',
        'ECCSECT163K1', 'ECCSECT233K1', 'ECCSECT283K1', 'ECCSECT409K1', 'ECCSECT571K1',
        'ECCSECT163R2', 'ECCSECT233R1', 'ECCSECT283R1', 'ECCSECT409R1', 'ECCSECT571R2'

    :param key_type:
    :return:
    """

    _CURVE_TYPES = {
        "ECCPRIME192V1": ec.SECP192R1(),  # duplicate
        "ECCPRIME256V1": ec.SECP256R1(),  # duplicate
        "ECCSECP192R1": ec.SECP192R1(),  # duplicate
        "ECCSECP224R1": ec.SECP224R1(),
        "ECCSECP256R1": ec.SECP256R1(),  # duplicate
        "ECCSECP384R1": ec.SECP384R1(),
        "ECCSECP521R1": ec.SECP521R1(),
        "ECCSECP256K1": ec.SECP256K1(),
        "ECCSECT163K1": ec.SECT163K1(),
        "ECCSECT233K1": ec.SECT233K1(),
        "ECCSECT283K1": ec.SECT283K1(),
        "ECCSECT409K1": ec.SECT409K1(),
        "ECCSECT571K1": ec.SECT571K1(),
        "ECCSECT163R2": ec.SECT163R2(),
        "ECCSECT233R1": ec.SECT233R1(),
        "ECCSECT283R1": ec.SECT283R1(),
        "ECCSECT409R1": ec.SECT409R1(),
        "ECCSECT571R2": ec.SECT571R1(),
    }

    if key_type not in CERTIFICATE_KEY_TYPES:
        raise Exception(
            "Invalid key type: {key_type}. Supported key types: {choices}".format(
                key_type=key_type, choices=",".join(CERTIFICATE_KEY_TYPES)
            )
        )

    if "RSA" in key_type:
        key_size = int(key_type[3:])
        return rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
    elif "ECC" in key_type:
        return ec.generate_private_key(
            _CURVE_TYPES[key_type], backend=default_backend()
        )


def key_to_alg(key):
    algorithm = jose.RS256
    # Determine alg with kty (and crv).
    if key.typ == "EC":
        crv = key.fields_to_partial_json().get("crv", None)
        if crv == "P-256" or not crv:
            algorithm = jose.ES256
        elif crv == "P-384":
            algorithm = jose.ES384
        elif crv == "P-521":
            algorithm = jose.ES512
    elif key.typ == "oct":
        algorithm = jose.HS256

    return algorithm


def check_cert_signature(cert, issuer_public_key):
    """
    Check a certificate's signature against an issuer public key.
    Before EC validation, make sure we support the algorithm, otherwise raise UnsupportedAlgorithm
    On success, returns None; on failure, raises UnsupportedAlgorithm or InvalidSignature.
    """
    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        # RSA requires padding, just to make life difficult for us poor developers :(
        if cert.signature_algorithm_oid == x509.SignatureAlgorithmOID.RSASSA_PSS:
            # In 2005, IETF devised a more secure padding scheme to replace PKCS #1 v1.5. To make sure that
            # nobody can easily support or use it, they mandated lots of complicated parameters, unlike any
            # other X.509 signature scheme.
            # https://tools.ietf.org/html/rfc4056
            raise UnsupportedAlgorithm("RSASSA-PSS not supported")
        else:
            padder = padding.PKCS1v15()
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padder,
            cert.signature_hash_algorithm,
        )
    elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey) and isinstance(
        ec.ECDSA(cert.signature_hash_algorithm), ec.ECDSA
    ):
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    else:
        raise UnsupportedAlgorithm(
            "Unsupported Algorithm '{var}'.".format(
                var=cert.signature_algorithm_oid._name
            )
        )


def is_selfsigned(cert):
    """
    Returns True if the certificate is self-signed.
    Returns False for failed verification or unsupported signing algorithm.
    """
    try:
        check_cert_signature(cert, cert.public_key())
        # If verification was successful, it's self-signed.
        return True
    except InvalidSignature:
        return False


def is_weekend(date):
    """
    Determines if a given date is on a weekend.

    :param date:
    :return:
    """
    if date.weekday() > 5:
        return True


def validate_conf(app, required_vars):
    """
    Ensures that the given fields are set in the applications conf.

    :param app:
    :param required_vars: list
    """
    for var in required_vars:
        if var not in app.config:
            raise InvalidConfiguration(
                f"Required variable '{var}' is not set in Lemur's conf."
            )


def check_validation(validation):
    """
    Checks that the given validation string compiles successfully.

    :param validation:
    :return str: The validation pattern, if compilation succeeds
    """

    try:
        compiled = re.compile(validation)
    except re.error as e:
        raise InvalidConfiguration(f"Validation {validation} couldn't compile. Reason: {e}")

    return compiled.pattern


# https://bitbucket.org/zzzeek/sqlalchemy/wiki/UsageRecipes/WindowedRangeQuery
def column_windows(session, column, windowsize):
    """Return a series of WHERE clauses against
    a given column that break it into windows.

    Result is an iterable of tuples, consisting of
    ((start, end), whereclause), where (start, end) are the ids.

    Requires a database that supports window functions,
    i.e. Postgresql, SQL Server, Oracle.

    Enhance this yourself !  Add a "where" argument
    so that windows of just a subset of rows can
    be computed.

    """

    def int_for_range(start_id, end_id):
        if end_id:
            return and_(column >= start_id, column < end_id)
        else:
            return column >= start_id

    q = session.query(
        column, func.row_number().over(order_by=column).label("rownum")
    ).from_self(column)

    if windowsize > 1:
        q = q.filter(sqlalchemy.text("rownum %% %d=1" % windowsize))

    intervals = [id for id, in q]

    while intervals:
        start = intervals.pop(0)
        if intervals:
            end = intervals[0]
        else:
            end = None
        yield int_for_range(start, end)


def windowed_query(q, column, windowsize):
    """"Break a Query into windows on a given column."""

    for whereclause in column_windows(q.session, column, windowsize):
        yield from q.filter(whereclause).order_by(column)


def truthiness(s):
    """If input string resembles something truthy then return True, else False."""

    return s.lower() in ("true", "yes", "on", "t", "1")


def find_matching_certificates_by_hash(cert, matching_certs):
    """Given a Cryptography-formatted certificate cert, and Lemur-formatted certificates (matching_certs),
    determine if any of the certificate hashes match and return the matches."""
    matching = []
    for c in matching_certs:
        if parse_certificate(c.body).fingerprint(hashes.SHA256()) == cert.fingerprint(
            hashes.SHA256()
        ):
            matching.append(c)
    return matching


def convert_pkcs7_bytes_to_pem(certs_pkcs7):
    """
    Given a list of certificates in pkcs7 encoding (bytes), covert them into a list of PEM encoded files
    :raises ValueError or ValidationError
    :param certs_pkcs7:
    :return: list of certs in PEM format
    """

    certificates = pkcs7.load_pem_pkcs7_certificates(certs_pkcs7)
    certificates_pem = []
    for cert in certificates:
        certificates_pem.append(pem.parse(cert.public_bytes(encoding=Encoding.PEM))[0])

    return certificates_pem


def get_certificate_via_tls(host, port, timeout=10):
    """
    Makes a TLS network connection to retrieve the current certificate for the specified host and port.

    Note that if the host is valid but the port is not, we'll wait for the timeout for the connection to fail,
    so this should remain low when doing bulk operations.

    :param host: Host to get certificate for
    :param port: Port to get certificate for
    :param timeout: Timeout in seconds
    """
    context = ssl.create_default_context()
    context.check_hostname = False  # we don't care about validating the cert
    context.verify_mode = ssl.CERT_NONE  # we don't care about validating the cert; it may be self-signed
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    conn.connect((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


def parse_serial(pem_certificate):
    """
    Parses a serial number from a PEM-encoded certificate.
    """
    x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_certificate)
    x509_cert.get_notAfter()
    parsed_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_certificate)
    return parsed_certificate.get_serial_number()


def data_encrypt(data):
    """
    takes an input and returns a base64 encoded encryption
    reusing the Vault DB encryption module
    :param data: string
    :return: base64 ciphertext
    """
    if not isinstance(data, str):
        data = str(data)
    ciphertext = Vault().process_bind_param(data, TEXT())
    return ciphertext.decode("utf8")


def data_decrypt(ciphertext):
    """
    takes a ciphertext and returns the respective string
    reusing the Vault DB encryption module
    :param ciphertext: base64 ciphertext
    :return: plaintext string
    """
    return Vault().process_result_value(ciphertext.encode("utf8"), TEXT())


def is_json(json_input):
    """
    Test if input is json
    :param json_input:
    :return: True or False
    """
    try:
        json.loads(json_input)
    except ValueError:
        return False
    return True


def drop_last_cert_from_chain(full_chain: str) -> str:
    """
    drops the last certificate from a certificate chai, if more than one CA/subCA in the chain
    :param full_chain: string of a certificate chain
    :return:  string of a new certificate chain, omitting the last certificate
    """
    if full_chain == '' or full_chain.count("BEGIN CERTIFICATE") <= 1:
        return full_chain
    full_chain_certs = CERT_PEM_REGEX.findall(full_chain.encode())
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, ''.join(cert.decode() for cert in full_chain_certs[:-1]).encode()
        ),
    ).decode()
    return pem_certificate
