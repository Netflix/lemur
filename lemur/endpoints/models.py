"""
.. module: lemur.endpoints.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a authority within Lemur.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, func, DateTime, PassiveDefault, Boolean, ForeignKey

from lemur.database import db

from lemur.models import policies_ciphers


class Cipher(db.Model):
    __tablename__ = 'ciphers'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)


class Policy(db.Model):
    ___tablename__ = 'policies'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=True)
    ciphers = relationship('Cipher', secondary=policies_ciphers, backref='policy')


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
    policy_id = Column(Integer, ForeignKey('policy.id'))
    policy = relationship('Policy', backref='endpoint')
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
