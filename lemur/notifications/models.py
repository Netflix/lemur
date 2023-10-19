"""
.. module: lemur.notifications.models
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy import Integer, String, Column, Boolean, Text
from sqlalchemy_utils import JSONType

from lemur.database import BaseModel
from lemur.plugins.base import plugins
from lemur.models import (
    certificate_notification_associations,
    pending_cert_notification_associations,
)


class Notification(BaseModel):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    label = Column(String(128), unique=True)
    description = Column(Text())
    options = Column(JSONType)
    active = Column(Boolean, default=True)
    plugin_name = Column(String(32))
    certificates = relationship(
        "Certificate",
        secondary=certificate_notification_associations,
        passive_deletes=True,
        backref="notification",
        cascade="all,delete",
    )
    pending_certificates = relationship(
        "PendingCertificate",
        secondary=pending_cert_notification_associations,
        passive_deletes=True,
        backref="notification",
        cascade="all,delete",
    )

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return f"Notification(label={self.label})"
