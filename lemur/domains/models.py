"""
.. module: lemur.domains.models
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import Column, Integer, String, Boolean

from lemur.database import BaseModel


class Domain(BaseModel):
    __tablename__ = "domains"
    __table_args__ = ()
    id = Column(Integer, primary_key=True)
    name = Column(String(256), index=True)
    sensitive = Column(Boolean, default=False)

    def __repr__(self):
        return f"Domain(name={self.name})"
