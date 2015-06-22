"""
.. module: lemur.accounts.models
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import relationship

from lemur.database import db


class Account(db.Model):
    __tablename__ = 'accounts'
    id = Column(Integer, primary_key=True)
    account_number = Column(String(32), unique=True)
    label = Column(String(32))
    notes = Column(Text())
    elbs = relationship("ELB", backref='account', cascade="all, delete, delete-orphan")

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        blob['elbs'] = [x.id for x in self.elbs]
        return blob

