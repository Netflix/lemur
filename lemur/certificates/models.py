"""
.. module: lemur.certificates.models
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from datetime import timedelta

import arrow
from cryptography import x509
from flask import current_app
from idna.core import InvalidCodepoint
from sentry_sdk import capture_exception
from sqlalchemy import (
    event,
    Integer,
    ForeignKey,
    String,
    DefaultClause,
    func,
    Column,
    Text,
    Boolean,
    Index,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql.expression import case, extract
from sqlalchemy_utils.types.arrow import ArrowType
from werkzeug.utils import cached_property


from lemur.common import defaults, utils, validators
from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.database import BaseModel
from lemur.domains.models import Domain
from lemur.extensions import metrics
from lemur.models import (
    certificate_source_associations,
    certificate_destination_associations,
    certificate_notification_associations,
    certificate_replacement_associations,
    roles_certificates,
    pending_cert_replacement_associations,
)
from lemur.plugins.base import plugins
from lemur.policies.models import RotationPolicy
from lemur.utils import Vault


def get_sequence(name):
    if "-" not in name:
        return name, None

    parts = name.split("-")

    # see if we have an int at the end of our name
    try:
        seq = int(parts[-1])
    except ValueError:
        return name, None

    # we might have a date at the end of our name
    if len(parts[-1]) == 8:
        return name, None

    root = "-".join(parts[:-1])
    return root, seq


def get_or_increase_name(name, serial):
    certificates = Certificate.query.filter(Certificate.name == name).all()

    if not certificates:
        return name

    serial_name = f"{name}-{hex(int(serial))[2:].upper()}"
    certificates = Certificate.query.filter(Certificate.name == serial_name).all()

    if not certificates:
        return serial_name

    certificates = Certificate.query.filter(
        Certificate.name.ilike(f"{serial_name}%")
    ).all()

    ends = [0]
    root, end = get_sequence(serial_name)
    for cert in certificates:
        root, end = get_sequence(cert.name)
        if end:
            ends.append(end)

    return f"{root}-{max(ends) + 1}"


class Certificate(BaseModel):
    __tablename__ = "certificates"
    __table_args__ = (
        Index(
            "ix_certificates_cn",
            "cn",
            postgresql_ops={"cn": "gin_trgm_ops"},
            postgresql_using="gin",
        ),
        Index("ix_certificates_serial", "serial"),
        # Index for ix_root_authority_id cannot be created here, and is only created in the migration file
        # since conditional indexes are not supported
    )
    id = Column(Integer, primary_key=True)
    ix = Index(
        "ix_certificates_id_desc", id.desc(), postgresql_using="btree", unique=True
    )
    external_id = Column(String(128))
    owner = Column(String(128), nullable=False)
    name = Column(String(256), unique=True, index=True)
    description = Column(String(1024))
    notify = Column(Boolean, default=True)

    body = Column(Text(), nullable=False)
    chain = Column(Text())
    csr = Column(Text())
    private_key = Column(Vault)

    issuer = Column(String(128))
    serial = Column(String(128))

    cn = Column(String(128))
    deleted = Column(Boolean, index=True, default=False)
    dns_provider_id = Column(
        Integer(), ForeignKey("dns_providers.id", ondelete="CASCADE"), nullable=True
    )

    not_before = Column(ArrowType)
    not_after = Column(ArrowType)
    not_after_ix = Index("ix_certificates_not_after", not_after.desc())

    date_created = Column(ArrowType, DefaultClause(func.now()), nullable=False)

    signing_algorithm = Column(String(128))
    status = Column(String(128))
    bits = Column(Integer())
    san = Column(String(1024))  # TODO this should be migrated to boolean

    rotation = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    authority_id = Column(Integer, ForeignKey("authorities.id", ondelete="CASCADE"))
    root_authority_id = Column(
        Integer, ForeignKey("authorities.id", ondelete="CASCADE")
    )
    rotation_policy_id = Column(Integer, ForeignKey("rotation_policies.id"))
    key_type = Column(String(128))

    notifications = relationship(
        "Notification",
        secondary=certificate_notification_associations,
        backref="certificate",
    )
    destinations = relationship(
        "Destination",
        secondary=certificate_destination_associations,
        backref="certificate",
    )
    sources = relationship(
        "Source", secondary=certificate_source_associations, backref="certificate"
    )
    domains = association_proxy('certificate_associations', 'domain')
    roles = relationship("Role", secondary=roles_certificates, backref="certificate")
    replaces = relationship(
        "Certificate",
        secondary=certificate_replacement_associations,
        primaryjoin=id == certificate_replacement_associations.c.certificate_id,  # noqa
        secondaryjoin=id
        == certificate_replacement_associations.c.replaced_certificate_id,  # noqa
        backref="replaced",
    )

    replaced_by_pending = relationship(
        "PendingCertificate",
        secondary=pending_cert_replacement_associations,
        backref="pending_replace",
    )

    logs = relationship("Log", backref="certificate")
    endpoints = relationship("Endpoint", backref="certificate")
    rotation_policy = relationship("RotationPolicy")
    sensitive_fields = ("private_key",)

    def __init__(self, **kwargs):
        self.body = kwargs["body"].strip()
        cert = self.parsed_cert

        self.issuer = defaults.issuer(cert)
        self.cn = defaults.common_name(cert)
        self.san = defaults.san(cert)
        self.not_before = defaults.not_before(cert)
        self.not_after = defaults.not_after(cert)
        self.serial = defaults.serial(cert)

        self.owner = kwargs["owner"]

        if kwargs.get("private_key"):
            self.private_key = kwargs["private_key"].strip()

        if kwargs.get("chain"):
            self.chain = kwargs["chain"].strip()

        if kwargs.get("csr"):
            self.csr = kwargs["csr"].strip()

        self.notify = kwargs.get("notify", True)
        self.notifications = kwargs.get("notifications", [])
        self.description = kwargs.get("description")
        self.roles = list(set(kwargs.get("roles", [])))
        self.replaces = kwargs.get("replaces", [])
        self.rotation = kwargs.get("rotation")
        self.rotation_policy = kwargs.get("rotation_policy")
        self.key_type = kwargs.get("key_type")
        self.signing_algorithm = defaults.signing_algorithm(cert)
        self.bits = defaults.bitstrength(cert)
        self.external_id = kwargs.get("external_id")
        self.authority_id = kwargs.get("authority_id")
        self.dns_provider_id = kwargs.get("dns_provider_id")

        for domain in defaults.domains(cert):
            self.domains.append(Domain(name=domain))

        # when destinations are appended they require a valid name
        # do not attempt to modify self.destinations before this step
        if kwargs.get("name"):
            self.name = get_or_increase_name(
                defaults.text_to_slug(kwargs["name"]), self.serial
            )
        else:
            self.name = get_or_increase_name(
                defaults.certificate_name(
                    self.cn, self.issuer, self.not_before, self.not_after, self.san, self.domains
                ),
                self.serial,
            )

        self.destinations = kwargs.get("destinations", [])

        # Check integrity before saving anything into the database.
        # For user-facing API calls, validation should also be done in schema validators.
        self.check_integrity()

    def check_integrity(self):
        """
        Integrity checks: Does the cert have a valid chain and matching private key?
        """
        if self.private_key:
            validators.verify_private_key_match(
                utils.parse_private_key(self.private_key),
                self.parsed_cert,
                error_class=AssertionError,
            )

        if self.chain:
            chain = [self.parsed_cert] + utils.parse_cert_chain(self.chain)
            validators.verify_cert_chain(chain, error_class=AssertionError)

    @cached_property
    def parsed_cert(self):
        assert self.body, "Certificate body not set"
        return utils.parse_certificate(self.body)

    @property
    def active(self):
        return self.notify

    @property
    def organization(self):
        return defaults.organization(self.parsed_cert)

    @property
    def organizational_unit(self):
        return defaults.organizational_unit(self.parsed_cert)

    @property
    def country(self):
        return defaults.country(self.parsed_cert)

    @property
    def state(self):
        return defaults.state(self.parsed_cert)

    @property
    def location(self):
        return defaults.location(self.parsed_cert)

    @property
    def distinguished_name(self):
        return self.parsed_cert.subject.rfc4514_string()

    """
    # Commenting this property as key_type is now added as a column. This code can be removed in future.
    @property
    def key_type(self):
        if isinstance(self.parsed_cert.public_key(), rsa.RSAPublicKey):
            return "RSA{key_size}".format(
                key_size=self.parsed_cert.public_key().key_size
            )
        elif isinstance(self.parsed_cert.public_key(), ec.EllipticCurvePublicKey):
            return get_key_type_from_ec_curve(self.parsed_cert.public_key().curve.name)
    """

    @property
    def validity_remaining(self):
        return abs(self.not_after - arrow.utcnow())

    @property
    def validity_range(self):
        return self.not_after - self.not_before

    @property
    def subject(self):
        return self.parsed_cert.subject

    @property
    def public_key(self):
        return self.parsed_cert.public_key()

    @hybrid_property
    def expired(self):
        # can't compare offset-naive and offset-aware datetimes
        if arrow.Arrow.fromdatetime(self.not_after) <= arrow.utcnow():
            return True

    @expired.expression  # type: ignore
    def expired(cls):
        return case([(cls.not_after <= arrow.utcnow(), True)], else_=False)

    @hybrid_property
    def revoked(self):
        if "revoked" == self.status:
            return True

    @revoked.expression  # type: ignore
    def revoked(cls):
        return case([(cls.status == "revoked", True)], else_=False)

    @hybrid_property
    def has_private_key(self):
        return self.private_key is not None

    @has_private_key.expression  # type: ignore
    def has_private_key(cls):
        return case([(cls.private_key.is_(None), True)], else_=False)

    @hybrid_property
    def in_rotation_window(self):
        """
        Determines if a certificate is available for rotation based
        on the rotation policy associated.
        :return:
        """
        now = arrow.utcnow()
        end = now + timedelta(days=self.rotation_policy.days)

        if self.not_after <= end:
            return True

    @in_rotation_window.expression  # type: ignore
    def in_rotation_window(cls):
        """
        Determines if a certificate is available for rotation based
        on the rotation policy associated.
        :return:
        """
        return case(
            [(extract("day", cls.not_after - func.now()) <= RotationPolicy.days, True)],
            else_=False,
        )

    @property
    def extensions(self):
        # setup default values
        return_extensions = {"sub_alt_names": {"names": []}}

        try:
            for extension in self.parsed_cert.extensions:
                value = extension.value
                if isinstance(value, x509.BasicConstraints):
                    return_extensions["basic_constraints"] = value

                elif isinstance(value, x509.SubjectAlternativeName):
                    return_extensions["sub_alt_names"]["names"] = value

                elif isinstance(value, x509.ExtendedKeyUsage):
                    return_extensions["extended_key_usage"] = value

                elif isinstance(value, x509.KeyUsage):
                    return_extensions["key_usage"] = value

                elif isinstance(value, x509.SubjectKeyIdentifier):
                    return_extensions["subject_key_identifier"] = {"include_ski": True}

                elif isinstance(value, x509.AuthorityInformationAccess):
                    return_extensions["certificate_info_access"] = {"include_aia": True}

                elif isinstance(value, x509.AuthorityKeyIdentifier):
                    aki = {"use_key_identifier": False, "use_authority_cert": False}

                    if value.key_identifier:
                        aki["use_key_identifier"] = True

                    if value.authority_cert_issuer:
                        aki["use_authority_cert"] = True

                    return_extensions["authority_key_identifier"] = aki

                elif isinstance(value, x509.CRLDistributionPoints):
                    return_extensions["crl_distribution_points"] = {
                        "include_crl_dp": value
                    }

                # TODO: Not supporting custom OIDs yet. https://github.com/Netflix/lemur/issues/665
                else:
                    current_app.logger.warning(
                        "Custom OIDs not yet supported for clone operation."
                    )
        except InvalidCodepoint as e:
            capture_exception()
            current_app.logger.warning(
                "Unable to parse extensions due to underscore in dns name"
            )
        except ValueError as e:
            capture_exception()
            current_app.logger.warning("Unable to parse")
            current_app.logger.exception(e)

        return return_extensions

    def __repr__(self):
        return f"Certificate(name={self.name})"


class CertificateAssociation(BaseModel):
    __tablename__ = 'certificate_associations'
    __table_args__ = (
        Index(
            "certificate_associations_ix",
            "domain_id",
            "certificate_id",
            unique=True
        ),
        Index(
            "certificate_associations_certificate_id_idx",
            "certificate_id",
        ),
    )
    domain_id = Column(Integer, ForeignKey("domains.id"), primary_key=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), primary_key=True)
    ports = Column(postgresql.ARRAY(Integer))
    certificate = relationship(Certificate,
                               backref=backref("certificate_associations",
                                               cascade="all, delete-orphan")
                               )
    domain = relationship("Domain")

    def __init__(self, domain=None, certificate=None, ports=None):
        self.certificate = certificate
        self.domain = domain
        self.ports = ports


@event.listens_for(Certificate.destinations, "append")
def update_destinations(target, value, initiator):
    """
    Attempt to upload certificate to the new destination

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    destination_plugin = plugins.get(value.plugin_name)
    status = FAILURE_METRIC_STATUS

    if target.expired:
        return
    try:
        if target.private_key or not destination_plugin.requires_key:
            destination_plugin.upload(
                target.name,
                target.body,
                target.private_key,
                target.chain,
                value.options,
            )
            status = SUCCESS_METRIC_STATUS
    except Exception as e:
        capture_exception()
        raise

    metrics.send(
        "destination_upload",
        "counter",
        1,
        metric_tags={
            "status": status,
            "certificate": target.name,
            "destination": value.label,
        },
    )


@event.listens_for(Certificate.replaces, "append")
def update_replacement(target, value, initiator):
    """
    When a certificate is marked as 'replaced' we should not notify.

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    value.notify = False
