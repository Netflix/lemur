"""
.. module: lemur.authorities.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a authority within Lemur.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, func, ForeignKey, DateTime, PassiveDefault, Boolean
from sqlalchemy.dialects.postgresql import JSON

from lemur.database import db
from lemur.certificates.models import get_cn, get_not_after, get_not_before


class Authority(db.Model):
    __tablename__ = 'authorities'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128))
    name = Column(String(128), unique=True)
    body = Column(Text())
    chain = Column(Text())
    bits = Column(Integer())
    cn = Column(String(128))
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    active = Column(Boolean, default=True)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)
    plugin_name = Column(String(64))
    description = Column(Text)
    options = Column(JSON)
    roles = relationship('Role', backref=db.backref('authority'), lazy='dynamic')
    user_id = Column(Integer, ForeignKey('users.id'))
    certificates = relationship("Certificate", backref='authority')

    def __init__(self, name, owner, plugin_name, body, roles=None, chain=None, description=None):
        self.name = name
        self.body = body
        self.chain = chain
        self.owner = owner
        self.description = description
        self.plugin_name = plugin_name
        cert = x509.load_pem_x509_certificate(str(body), default_backend())
        self.cn = get_cn(cert)
        self.not_before = get_not_before(cert)
        self.not_after = get_not_after(cert)

        if roles:
            self.roles = roles

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        return blob
