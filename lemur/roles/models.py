"""
.. module: models
    :platform: unix
    :synopsis: This module contains all of the models need to create a role within Lemur

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
import os
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, ForeignKey

from sqlalchemy_utils import EncryptedType

from lemur.database import db
from lemur.models import roles_users


class Role(db.Model):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True)
    username = Column(String(128))
    password = Column(EncryptedType(String, os.environ.get('LEMUR_ENCRYPTION_KEY')))
    description = Column(Text)
    authority_id = Column(Integer, ForeignKey('authorities.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    users = relationship("User", secondary=roles_users, passive_deletes=True, backref="role", cascade='all,delete')

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        return blob
