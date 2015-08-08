"""
.. module: lemur.certificates.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import datetime
from flask import current_app

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import relationship
from sqlalchemy import event, Integer, ForeignKey, String, DateTime, PassiveDefault, func, Column, Text, Boolean

from sqlalchemy_utils import EncryptedType

from lemur.utils import get_key
from lemur.database import db
from lemur.plugins.base import plugins

from lemur.domains.models import Domain

from lemur.constants import SAN_NAMING_TEMPLATE, DEFAULT_NAMING_TEMPLATE

from lemur.models import certificate_associations, certificate_source_associations, \
    certificate_destination_associations, certificate_notification_associations


def create_name(issuer, not_before, not_after, subject, san):
    """
    Create a name for our certificate. A naming standard
    is based on a series of templates. The name includes
    useful information such as Common Name, Validation dates,
    and Issuer.

    :rtype : str
    :return:
    """
    if san:
        t = SAN_NAMING_TEMPLATE
    else:
        t = DEFAULT_NAMING_TEMPLATE

    temp = t.format(
        subject=subject,
        issuer=issuer,
        not_before=not_before.strftime('%Y%m%d'),
        not_after=not_after.strftime('%Y%m%d')
    )

    # NOTE we may want to give more control over naming
    # aws doesn't allow special chars except '-'
    disallowed_chars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
    disallowed_chars = disallowed_chars.replace("-", "")
    disallowed_chars = disallowed_chars.replace(".", "")
    temp = temp.replace('*', "WILDCARD")

    for c in disallowed_chars:
        temp = temp.replace(c, "")

    # white space is silly too
    return temp.replace(" ", "-")


def cert_get_cn(cert):
    """
    Attempts to get a sane common name from a given certificate.

    :param cert:
    :return: Common name or None
    """
    return cert.subject.get_attributes_for_oid(
        x509.OID_COMMON_NAME
    )[0].value.strip()


def cert_get_domains(cert):
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
    except Exception as e:
        current_app.logger.warning("Failed to get SubjectAltName: {0}".format(e))

    return domains


def cert_get_serial(cert):
    """
    Fetch the serial number from the certificate.

    :param cert:
    :return: serial number
    """
    return cert.serial


def cert_is_san(cert):
    """
    Determines if a given certificate is a SAN certificate.
    SAN certificates are simply certificates that cover multiple domains.

    :param cert:
    :return: Bool
    """
    if len(cert_get_domains(cert)) > 1:
        return True


def cert_is_wildcard(cert):
    """
    Determines if certificate is a wildcard certificate.

    :param cert:
    :return: Bool
    """
    domains = cert_get_domains(cert)
    if len(domains) == 1 and domains[0][0:1] == "*":
        return True

    if cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value[0:1] == "*":
        return True


def cert_get_bitstrength(cert):
    """
    Calculates a certificates public key bit length.

    :param cert:
    :return: Integer
    """
    return cert.public_key().key_size


def cert_get_issuer(cert):
    """
    Gets a sane issuer from a given certificate.

    :param cert:
    :return: Issuer
    """
    delchars = ''.join(c for c in map(chr, range(256)) if not c.isalnum())
    try:
        issuer = str(cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value)
        for c in delchars:
            issuer = issuer.replace(c, "")
        return issuer
    except Exception as e:
        current_app.logger.error("Unable to get issuer! {0}".format(e))


def cert_get_not_before(cert):
    """
    Gets the naive datetime of the certificates 'not_before' field.
    This field denotes the first date in time which the given certificate
    is valid.

    :param cert:
    :return: Datetime
    """
    return cert.not_valid_before


def cert_get_not_after(cert):
    """
    Gets the naive datetime of the certificates 'not_after' field.
    This field denotes the last date in time which the given certificate
    is valid.

    :param cert:
    :return: Datetime
    """
    return cert.not_valid_after


def get_name_from_arn(arn):
    """
    Extract the certificate name from an arn.

    :param arn: IAM SSL arn
    :return: name of the certificate as uploaded to AWS
    """
    return arn.split("/", 1)[1]


def get_account_number(arn):
    """
    Extract the account number from an arn.

    :param arn: IAM SSL arn
    :return: account number associated with ARN
    """
    return arn.split(":")[4]


class Certificate(db.Model):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128))
    body = Column(Text())
    private_key = Column(EncryptedType(String, get_key))
    status = Column(String(128))
    deleted = Column(Boolean, index=True)
    name = Column(String(128))
    chain = Column(Text())
    bits = Column(Integer())
    issuer = Column(String(128))
    serial = Column(String(128))
    cn = Column(String(128))
    description = Column(String(1024))
    active = Column(Boolean, default=True)
    san = Column(String(1024))
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    authority_id = Column(Integer, ForeignKey('authorities.id'))
    notifications = relationship("Notification", secondary=certificate_notification_associations, backref='certificate')
    destinations = relationship("Destination", secondary=certificate_destination_associations, backref='certificate')
    sources = relationship("Source", secondary=certificate_source_associations, backref='certificate')
    domains = relationship("Domain", secondary=certificate_associations, backref="certificate")

    def __init__(self, body, private_key=None, chain=None):
        self.body = body
        # We encrypt the private_key on creation
        self.private_key = private_key
        self.chain = chain
        cert = x509.load_pem_x509_certificate(str(self.body), default_backend())
        self.bits = cert_get_bitstrength(cert)
        self.issuer = cert_get_issuer(cert)
        self.serial = cert_get_serial(cert)
        self.cn = cert_get_cn(cert)
        self.san = cert_is_san(cert)
        self.not_before = cert_get_not_before(cert)
        self.not_after = cert_get_not_after(cert)
        self.name = create_name(self.issuer, self.not_before, self.not_after, self.cn, self.san)

        for domain in cert_get_domains(cert):
            self.domains.append(Domain(name=domain))

    @property
    def is_expired(self):
        if self.not_after < datetime.datetime.now():
            return True

    @property
    def is_unused(self):
        if self.elb_listeners.count() == 0:
            return True

    @property
    def is_revoked(self):
        # we might not yet know the condition of the cert
        if self.status:
            if 'revoked' in self.status:
                return True

    def get_arn(self, account_number):
        """
        Generate a valid AWS IAM arn

        :rtype : str
        :param account_number:
        :return:
        """
        return "arn:aws:iam::{}:server-certificate/{}".format(account_number, self.name)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


@event.listens_for(Certificate.destinations, 'append')
def update_destinations(target, value, initiator):
    destination_plugin = plugins.get(value.plugin_name)
    destination_plugin.upload(target.name, target.body, target.private_key, target.chain, value.options)
