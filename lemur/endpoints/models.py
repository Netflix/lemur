"""
.. module: lemur.endpoints.models
    :platform: unix
    :synopsis: This module contains all of the models need to create an authority within Lemur.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import arrow
from sqlalchemy.orm import relationship
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql.expression import case

from sqlalchemy_utils import ArrowType

from lemur.database import BaseModel

from lemur.models import policies_ciphers

BAD_CIPHERS = ["Protocol-SSLv3", "Protocol-SSLv2", "Protocol-TLSv1"]


class Cipher(BaseModel):
    __tablename__ = "ciphers"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)

    @hybrid_property
    def deprecated(self):
        return self.name in BAD_CIPHERS

    @deprecated.expression  # type: ignore
    def deprecated(cls):
        return case([(cls.name in BAD_CIPHERS, True)], else_=False)


class Policy(BaseModel):
    ___tablename__ = "policies"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=True)
    ciphers = relationship("Cipher", secondary=policies_ciphers, backref="policy")


class EndpointDnsAlias(BaseModel):
    __tablename__ = "endpoint_dnsalias"
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey('endpoints.id'))
    alias = Column(String(256))


class Endpoint(BaseModel):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True)
    owner = Column(String(128))
    name = Column(String(128))
    dnsname = Column(String(256))
    aliases = relationship("EndpointDnsAlias", backref="endpoint")
    type = Column(String(128))
    active = Column(Boolean, default=True)
    port = Column(Integer)
    policy_id = Column(Integer, ForeignKey("policy.id"))
    policy = relationship("Policy", backref="endpoint")
    certificate_id = Column(Integer, ForeignKey("certificates.id"))
    certificate_path = Column(String(256))
    registry_type = Column(String(128))
    source_id = Column(Integer, ForeignKey("sources.id"))
    sensitive = Column(Boolean, default=False)
    source = relationship("Source", back_populates="endpoints")
    last_updated = Column(ArrowType, default=arrow.utcnow, nullable=False)
    date_created = Column(
        ArrowType, default=arrow.utcnow, onupdate=arrow.utcnow, nullable=False
    )

    replaced = association_proxy("certificate", "replaced")

    @property
    def dns_aliases(self):
        aliases = []
        for alias in self.aliases:
            aliases.append(alias.alias)
        return aliases

    @property
    def source_label(self):
        return self.source.label

    @property
    def issues(self):
        issues = []

        for cipher in self.policy.ciphers:
            if cipher.deprecated:
                issues.append(
                    {
                        "name": "deprecated cipher",
                        "value": "{} has been deprecated consider removing it.".format(
                            cipher.name
                        ),
                    }
                )

        if self.certificate.expired:
            issues.append(
                {
                    "name": "expired certificate",
                    "value": "There is an expired certificate attached to this endpoint consider replacing it.",
                }
            )

        if self.certificate.revoked:
            issues.append(
                {
                    "name": "revoked",
                    "value": "There is a revoked certificate attached to this endpoint consider replacing it.",
                }
            )

        return issues

    def __repr__(self):
        return f"Endpoint(name={self.name})"
