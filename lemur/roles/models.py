"""
.. module: lemur.roles.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a role within Lemur

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, ForeignKey

from lemur.database import db
from lemur.utils import Vault
from lemur.models import roles_users


class Role(db.Model):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True)
    username = Column(String(128))
    password = Column(Vault)
    description = Column(Text)
    authority_id = Column(Integer, ForeignKey('authorities.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    users = relationship("User", secondary=roles_users, passive_deletes=True, backref="role", cascade='all,delete')
