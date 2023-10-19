"""
.. module: lemur.roles.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a role within Lemur

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, Integer, String, Text, ForeignKey

from lemur.database import BaseModel
from lemur.utils import Vault
from lemur.models import (
    roles_users,
    roles_authorities,
    roles_certificates,
    pending_cert_role_associations,
)


class Role(BaseModel):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True)
    username = Column(String(128))
    password = Column(Vault)
    description = Column(Text)
    authority_id = Column(Integer, ForeignKey("authorities.id"))
    authorities = relationship(
        "Authority",
        secondary=roles_authorities,
        passive_deletes=True,
        backref="role",
        cascade="all,delete",
    )
    user_id = Column(Integer, ForeignKey("users.id"))
    third_party = Column(Boolean)
    users = relationship(
        "User", secondary=roles_users, passive_deletes=True, backref="role"
    )
    certificates = relationship(
        "Certificate", secondary=roles_certificates, backref="role"
    )
    pending_certificates = relationship(
        "PendingCertificate", secondary=pending_cert_role_associations, backref="role"
    )

    sensitive_fields = ("password",)

    def __repr__(self):
        return f"Role(name={self.name})"
