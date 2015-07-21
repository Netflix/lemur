"""
.. module: lemur.elbs.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, BigInteger, String, DateTime, PassiveDefault, func
from sqlalchemy.orm import relationship

from lemur.database import db
from lemur.listeners.models import Listener


class ELB(db.Model):
    __tablename__ = 'elbs'
    id = Column(BigInteger, primary_key=True)
    # account_id = Column(BigInteger, ForeignKey("accounts.id"), index=True)
    region = Column(String(32))
    name = Column(String(128))
    vpc_id = Column(String(128))
    scheme = Column(String(128))
    dns_name = Column(String(128))
    listeners = relationship("Listener", backref='elb', cascade="all, delete, delete-orphan")
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)

    def __init__(self, elb_obj=None):
        if elb_obj:
            self.region = elb_obj.connection.region.name
            self.name = elb_obj.name
            self.vpc_id = elb_obj.vpc_id
            self.scheme = elb_obj.scheme
            self.dns_name = elb_obj.dns_name
            for listener in elb_obj.listeners:
                self.listeners.append(Listener(listener))

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        del blob['date_created']
        return blob
