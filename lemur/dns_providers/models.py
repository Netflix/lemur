from sqlalchemy import Column, Integer, PrimaryKeyConstraint, String, text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy_utils import ArrowType

from lemur.database import db


class DnsProviders(db.Model):
    __tablename__ = 'dns_providers'
    id = Column(Integer(), primary_key=True)
    name = Column(String(length=256), unique=True, nullable=True)
    description = Column(String(length=1024), nullable=True)
    provider_type = Column(String(length=256), nullable=True)
    credentials = Column(String(length=256), nullable=True)
    api_endpoint = Column(String(length=256), nullable=True)
    date_created = Column(ArrowType(), server_default=text('now()'), nullable=False)
    status = Column(String(length=128), nullable=True)
    options = Column(JSON, nullable=True)
    domains = Column(JSON, nullable=True)
