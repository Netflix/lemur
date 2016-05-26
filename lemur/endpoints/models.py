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
from sqlalchemy import Column, Integer, String, func, DateTime, PassiveDefault, Boolean

from lemur.database import db


class Endpoint(db.Model):
    __tablename__ = 'endpoints'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128), nullable=False)
    name = Column(String(128), unique=True)
    type = Column(String(128))
    active = Column(Boolean, default=True)
    port = Column(Integer)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)
    policy = relationship("Policy", backref='endpoint')
    destinations = relationship("Destination", backref='endpoint')
    certificate = relationship("Certificate", backref='endpoint')


class Policy(db.Model):
    ___tablename__ = 'policies'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), nullable=True)
    ciphers = Column(JSONType)
