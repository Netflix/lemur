"""
.. module: lemur.domains.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import Column, Integer, String

from lemur.database import db


class Domain(db.Model):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True)
    name = Column(String(256))

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def serialize(self):
        blob = self.as_dict()
        blob['certificates'] = [x.id for x in self.certificate]
        return blob

