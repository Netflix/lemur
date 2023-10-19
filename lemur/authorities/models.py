"""
.. module: lemur.authorities.models
    :platform: unix
    :synopsis: This module contains all of the models need to create an authority within Lemur.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import json

from flask import current_app
from sqlalchemy.orm import relationship
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    func,
    ForeignKey,
    DateTime,
    DefaultClause,
    Boolean,
)
from sqlalchemy.dialects.postgresql import JSON

from lemur.database import BaseModel, db
from lemur.plugins.base import plugins
from lemur.models import roles_authorities


class Authority(BaseModel):
    __tablename__ = "authorities"
    id = Column(Integer, primary_key=True)
    owner = Column(String(128), nullable=False)
    name = Column(String(128), unique=True)
    body = Column(Text())
    chain = Column(Text())
    active = Column(Boolean, default=True)
    plugin_name = Column(String(64))
    description = Column(Text)
    options = Column(JSON)
    date_created = Column(DateTime, DefaultClause(func.now()), nullable=False)
    roles = relationship(
        "Role",
        secondary=roles_authorities,
        passive_deletes=True,
        backref=db.backref("authority"),
    )
    user_id = Column(Integer, ForeignKey("users.id"))
    authority_certificate = relationship(
        "Certificate",
        backref="root_authority",
        uselist=False,
        foreign_keys="Certificate.root_authority_id",
    )
    certificates = relationship(
        "Certificate", backref="authority", foreign_keys="Certificate.authority_id"
    )

    authority_pending_certificate = relationship(
        "PendingCertificate",
        backref="root_authority",
        uselist=False,
        foreign_keys="PendingCertificate.root_authority_id",
    )
    pending_certificates = relationship(
        "PendingCertificate",
        backref="authority",
        foreign_keys="PendingCertificate.authority_id",
    )

    def __init__(self, **kwargs):
        self.owner = kwargs["owner"]
        self.roles = kwargs.get("roles", [])
        self.name = kwargs.get("name")
        self.description = kwargs.get("description")
        self.authority_certificate = kwargs["authority_certificate"]
        self.plugin_name = kwargs["plugin"]["slug"]
        self.options = kwargs.get("options")

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    @property
    def is_cab_compliant(self):
        """
        Parse the options to find whether authority is CAB Forum Compliant,
        i.e., adhering to the CA/Browser Forum Baseline Requirements.
        Returns None if option is not available
        """
        if not self.options:
            return None

        options_array = json.loads(self.options)
        if isinstance(options_array, list):
            for option in options_array:
                if "name" in option and option["name"] == 'cab_compliant':
                    return option["value"]

        return None

    @property
    def is_private_authority(self):
        """
        Tells if authority is private/internal. In other words, it is not publicly trusted.
        If plugin is configured in list LEMUR_PRIVATE_AUTHORITY_PLUGIN_NAMES, the authority is treated as private
        :return: True if private, False otherwise
        """
        return self.plugin_name in current_app.config.get("LEMUR_PRIVATE_AUTHORITY_PLUGIN_NAMES", [])

    @property
    def max_issuance_days(self):
        if self.is_cab_compliant:
            return current_app.config.get("PUBLIC_CA_MAX_VALIDITY_DAYS", 397)

    @property
    def default_validity_days(self):
        if self.is_cab_compliant:
            return current_app.config.get("PUBLIC_CA_MAX_VALIDITY_DAYS", 397)

        return current_app.config.get("DEFAULT_VALIDITY_DAYS", 365)  # 1 year default

    def __repr__(self):
        return f"Authority(name={self.name})"

    @property
    def is_cn_optional(self):
        """
        Parse the options to find whether common name is treated as an optional field.
        Returns False if option is not available
        """
        if not self.options:
            return False

        options_array = json.loads(self.options)
        if isinstance(options_array, list):
            for option in options_array:
                if "name" in option and option["name"] == 'cn_optional':
                    return option["value"]

        return False
