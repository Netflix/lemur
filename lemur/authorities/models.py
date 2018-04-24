"""
.. module: lemur.authorities.models
    :platform: unix
    :synopsis: This module contains all of the models need to create an authority within Lemur.
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, func, ForeignKey, DateTime, PassiveDefault, Boolean
from sqlalchemy.dialects.postgresql import JSON

from lemur.database import db
from lemur.plugins.base import plugins
from lemur.models import roles_authorities


class Authority(db.Model):
    __tablename__ = 'authorities'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128), nullable=False)
    name = Column(String(128), unique=True)
    body = Column(Text())
    chain = Column(Text())
    active = Column(Boolean, default=True)
    plugin_name = Column(String(64))
    description = Column(Text)
    options = Column(JSON)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)
    roles = relationship('Role', secondary=roles_authorities, passive_deletes=True, backref=db.backref('authority'), lazy='dynamic')
    user_id = Column(Integer, ForeignKey('users.id'))
    authority_certificate = relationship("Certificate", backref='root_authority', uselist=False, foreign_keys='Certificate.root_authority_id')
    certificates = relationship("Certificate", backref='authority', foreign_keys='Certificate.authority_id')

    authority_pending_certificate = relationship("PendingCertificate", backref='root_authority', uselist=False, foreign_keys='PendingCertificate.root_authority_id')
    pending_certificates = relationship('PendingCertificate', backref='authority', foreign_keys='PendingCertificate.authority_id')

    def __init__(self, **kwargs):
        self.owner = kwargs['owner']
        self.roles = kwargs.get('roles', [])
        self.name = kwargs.get('name')
        self.description = kwargs.get('description')
        self.authority_certificate = kwargs['authority_certificate']
        self.plugin_name = kwargs['plugin']['slug']
        self.options = kwargs.get('options')

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return "Authority(name={name})".format(name=self.name)
