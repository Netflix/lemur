from sqlalchemy import Column, Integer, String, text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import relationship
from sqlalchemy_utils import ArrowType

from lemur.database import BaseModel
from lemur.plugins.base import plugins
from lemur.utils import Vault


class DnsProvider(BaseModel):
    __tablename__ = "dns_providers"
    id = Column(Integer(), primary_key=True)
    name = Column(String(length=256), unique=True, nullable=True)
    description = Column(String(length=1024), nullable=True)
    provider_type = Column(String(length=256), nullable=True)
    credentials = Column(Vault, nullable=True)
    api_endpoint = Column(String(length=256), nullable=True)
    date_created = Column(ArrowType(), server_default=text("now()"), nullable=False)
    status = Column(String(length=128), nullable=True)
    options = Column(JSON, nullable=True)
    domains = Column(JSON, nullable=True)
    certificates = relationship(
        "Certificate",
        backref="dns_provider",
        foreign_keys="Certificate.dns_provider_id",
        lazy="dynamic",
    )

    def __init__(self, name, description, provider_type, credentials):
        self.name = name
        self.description = description
        self.provider_type = provider_type
        self.credentials = credentials

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return f"DnsProvider(name={self.name})"
