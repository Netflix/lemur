"""
.. module: lemur.endpoints.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a authority within Lemur.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy_utils import JSONType
from sqlalchemy import Column, Integer, String, func, DateTime, PassiveDefault, Boolean, ForeignKey

from lemur.database import db


class Policy(db.Model):
    ___tablename__ = 'policies'
    id = Column(Integer, primary_key=True)
    endpoint_id = Column(Integer, ForeignKey('endpoints.id'))
    name = Column(String(128), nullable=True)
    ciphers = Column(JSONType)


class Endpoint(db.Model):
    __tablename__ = 'endpoints'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128))
    name = Column(String(128))
    dnsname = Column(String(256))
    type = Column(String(128))
    active = Column(Boolean, default=True)
    port = Column(Integer)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)
    policy = relationship('Policy', backref='endpoint', uselist=False)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
