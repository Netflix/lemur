"""
.. module: lemur.pending_certificates.models
    Copyright (c) 2018 and onwards Netflix, Inc.  All rights reserved.
.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""
from datetime import datetime as dt

from sqlalchemy import (
    Integer,
    ForeignKey,
    String,
    DefaultClause,
    func,
    Column,
    Text,
    Boolean,
)
from sqlalchemy.orm import relationship
from sqlalchemy_utils import JSONType
from sqlalchemy_utils.types.arrow import ArrowType

from lemur.certificates.models import get_sequence
from lemur.common import defaults, utils
from lemur.database import BaseModel
from lemur.domains.models import Domain
from lemur.models import (
    pending_cert_source_associations,
    pending_cert_destination_associations,
    pending_cert_notification_associations,
    pending_cert_replacement_associations,
    pending_cert_role_associations,
)
from lemur.utils import Vault


def get_or_increase_name(name, serial):
    certificates = PendingCertificate.query.filter(
        PendingCertificate.name.ilike(f"{name}%")
    ).all()

    if not certificates:
        return name

    serial_name = f"{name}-{hex(int(serial))[2:].upper()}"
    certificates = PendingCertificate.query.filter(
        PendingCertificate.name.ilike(f"{serial_name}%")
    ).all()

    if not certificates:
        return serial_name

    ends = [0]
    root, end = get_sequence(serial_name)
    for cert in certificates:
        root, end = get_sequence(cert.name)
        if end:
            ends.append(end)

    return f"{root}-{max(ends) + 1}"


class PendingCertificate(BaseModel):
    __tablename__ = "pending_certs"
    id = Column(Integer, primary_key=True)
    external_id = Column(String(128))
    owner = Column(String(128), nullable=False)
    name = Column(String(256), unique=True)
    description = Column(String(1024))
    notify = Column(Boolean, default=True)
    number_attempts = Column(Integer)
    rename = Column(Boolean, default=True)
    resolved = Column(Boolean, default=False)
    resolved_cert_id = Column(Integer, nullable=True)

    cn = Column(String(128))
    csr = Column(Text(), nullable=False)
    chain = Column(Text())
    private_key = Column(Vault, nullable=True)

    date_created = Column(ArrowType, DefaultClause(func.now()), nullable=False)
    dns_provider_id = Column(
        Integer, ForeignKey("dns_providers.id", ondelete="CASCADE")
    )

    status = Column(Text(), nullable=True)
    last_updated = Column(
        ArrowType, DefaultClause(func.now()), onupdate=func.now(), nullable=False
    )

    rotation = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    authority_id = Column(Integer, ForeignKey("authorities.id", ondelete="CASCADE"))
    root_authority_id = Column(
        Integer, ForeignKey("authorities.id", ondelete="CASCADE")
    )
    rotation_policy_id = Column(Integer, ForeignKey("rotation_policies.id"))

    notifications = relationship(
        "Notification",
        secondary=pending_cert_notification_associations,
        backref="pending_cert",
        passive_deletes=True,
    )
    destinations = relationship(
        "Destination",
        secondary=pending_cert_destination_associations,
        backref="pending_cert",
        passive_deletes=True,
    )
    sources = relationship(
        "Source",
        secondary=pending_cert_source_associations,
        backref="pending_cert",
        passive_deletes=True,
    )
    roles = relationship(
        "Role",
        secondary=pending_cert_role_associations,
        backref="pending_cert",
        passive_deletes=True,
    )
    replaces = relationship(
        "Certificate",
        secondary=pending_cert_replacement_associations,
        backref="pending_cert",
        passive_deletes=True,
    )
    options = Column(JSONType)

    rotation_policy = relationship("RotationPolicy")

    sensitive_fields = ("private_key",)

    def __init__(self, **kwargs):
        self.csr = kwargs.get("csr")
        self.private_key = kwargs.get("private_key", "")
        if self.private_key:
            # If the request does not send private key, the key exists but the value is None
            self.private_key = self.private_key.strip()
        self.external_id = kwargs.get("external_id")

        domains = []
        if kwargs.get("extensions"):
            domains = [Domain(name=x.value) for x in kwargs["extensions"]["sub_alt_names"]["names"]]

        # when destinations are appended they require a valid name.
        if kwargs.get("name"):
            self.name = get_or_increase_name(defaults.text_to_slug(kwargs["name"]), 0)
            self.rename = False
        else:
            # TODO: Fix auto-generated name, it should be renamed on creation
            self.name = get_or_increase_name(
                defaults.certificate_name(
                    kwargs["common_name"],
                    kwargs["authority"].name,
                    dt.now(),
                    dt.now(),
                    len(domains) > 1,
                    domains
                ),
                self.external_id,
            )
            self.rename = True

        self.cn = defaults.common_name(utils.parse_csr(self.csr))
        self.owner = kwargs["owner"]
        self.number_attempts = 0

        if kwargs.get("chain"):
            self.chain = kwargs["chain"].strip()

        self.notify = kwargs.get("notify", True)
        self.destinations = kwargs.get("destinations", [])
        self.notifications = kwargs.get("notifications", [])
        self.description = kwargs.get("description")
        self.roles = list(set(kwargs.get("roles", [])))
        self.replaces = kwargs.get("replaces", [])
        self.rotation = kwargs.get("rotation")
        self.rotation_policy = kwargs.get("rotation_policy")
        try:
            self.dns_provider_id = kwargs.get("dns_provider").id
        except (AttributeError, KeyError, TypeError, Exception):
            pass
