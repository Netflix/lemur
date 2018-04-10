from sqlalchemy import Column, Integer, PrimaryKeyConstraint, String, text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy_utils import ArrowType

from lemur.database import db


class DnsProviders(db.Model):
    db.Table('dns_providers',
             Column('id', Integer(), nullable=False),
             Column('name', String(length=256), nullable=True),
             Column('description', String(length=1024), nullable=True),
             Column('provider_type', String(length=256), nullable=True),
             Column('credentials', String(length=256), nullable=True),
             Column('api_endpoint', String(length=256), nullable=True),
             Column('date_created', ArrowType(), server_default=text('now()'), nullable=False),
             Column('status', String(length=128), nullable=True),
             Column('options', JSON),
             PrimaryKeyConstraint('id'),
             UniqueConstraint('name'))