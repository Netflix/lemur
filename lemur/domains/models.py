"""
.. module: lemur.domains.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import Column, Integer, String, Boolean

from lemur.database import db


class Domain(db.Model):
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True)
    name = Column(String(256))
    sensitive = Column(Boolean, default=False)
