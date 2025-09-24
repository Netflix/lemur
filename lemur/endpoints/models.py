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
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql.expression import case

from sqlalchemy_utils import ArrowType

from lemur.database import db

from lemur.models import policies_ciphers, EndpointsCertificates

from deprecated import deprecated

BAD_CIPHERS = ["Protocol-SSLv3", "Protocol-SSLv2", "Protocol-TLSv1"]


class Cipher(db.Model):
    __tablename__ = "ciphers"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)

    @hybrid_property
    def deprecated(self):
        return self.name in BAD_CIPHERS

    @deprecated.expression
    def deprecated(cls):
        return case([(cls.name in BAD_CIPHERS, True)], else_=False)


class Policy(db.Model):
    ___tablename__ = "policies"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=True)
    ciphers = relationship("Cipher", secondary=policies_ciphers, backref="policy")


class EndpointDnsAlias(db.Model):
    __tablename__ = "endpoint_dnsalias"
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    alias = Column(String(256))


class Endpoint(db.Model):
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
    certificates_assoc = relationship(
        "EndpointsCertificates", back_populates="endpoint", cascade="all, delete-orphan"
    )
    certificates = association_proxy(
        "certificates_assoc",
        "certificate",
        creator=lambda cert: EndpointsCertificates(certificate=cert),
    )
    registry_type = Column(String(128))
    source_id = Column(Integer, ForeignKey("sources.id"))
    sensitive = Column(Boolean, default=False)
    source = relationship("Source", back_populates="endpoints")
    last_updated = Column(ArrowType, default=arrow.utcnow, nullable=False)
    date_created = Column(
        ArrowType, default=arrow.utcnow, onupdate=arrow.utcnow, nullable=False
    )

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
                        "value": "{0} has been deprecated consider removing it.".format(
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

    @hybrid_property
    def primary_certificate(self):
        """Returns the primary certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.primary:
                return assoc.certificate
        return None

    @primary_certificate.setter
    def primary_certificate(self, cert):
        """Sets the primary certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.primary:
                assoc.certificate = cert
                return
        self.certificates_assoc.append(
            EndpointsCertificates(
                certificate=cert, endpoint=self, primary=True, path=""
            )
        )

    @hybrid_property
    def sni_certificates(self):
        """Returns the SNI certificates associated with the endpoint."""
        return [
            assoc.certificate for assoc in self.certificates_assoc if not assoc.primary
        ]

    @sni_certificates.setter
    def sni_certificates(self, certs):
        """Sets the SNI certificates associated with the endpoint."""
        self.certificates_assoc = [
            assoc for assoc in self.certificates_assoc if assoc.primary
        ]
        for cert in certs:
            self.add_sni_certificate(cert)

    def add_sni_certificate(self, certificate, path=""):
        """Associates a SNI certificate with the endpoint."""
        self.certificates_assoc.append(
            EndpointsCertificates(
                certificate=certificate, endpoint=self, primary=False, path=path
            )
        )

    def replace_sni_certificate(self, old_certificate, new_certificate, path=""):
        """Replaces the SNI certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.certificate == old_certificate:
                assoc.certificate = new_certificate
                assoc.path = path

    def set_certificate_path(self, certificate, path):
        """Sets the path of the given certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.certificate == certificate:
                assoc.path = path

    @hybrid_property
    @deprecated(
        "The certificate attribute is deprecated and will be removed soon. Use Endpoint.primary_certificate instead."
    )
    def certificate(self):
        """DEPRECATED: Returns the primary certificate associated with the endpoint."""
        return self.primary_certificate

    @certificate.setter
    @deprecated(
        "The certificate attribute is deprecated and will be removed soon. Use Endpoint.primary_certificate instead."
    )
    def certificate(self, cert):
        """DEPRECATED: Sets the primary certificate associated with the endpoint."""
        self.primary_certificate = cert

    @hybrid_property
    @deprecated(
        "The certificate_path attribute is deprecated and will be removed soon. Retrieve from Endpoint.certificates_assoc instead."
    )
    def certificate_path(self):
        """DEPRECATED: Returns the path of the primary certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.primary:
                return assoc.path
        return None

    @certificate_path.setter
    @deprecated(
        "The certificate_path attribute is deprecated and will be removed soon. Retrieve from Endpoint.certificates_assoc instead."
    )
    def certificate_path(self, path):
        """DEPRECATED: Sets the path of the primary certificate associated with the endpoint."""
        for assoc in self.certificates_assoc:
            if assoc.primary:
                assoc.path = path

    def __repr__(self):
        return "Endpoint(name={name})".format(name=self.name)
