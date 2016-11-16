"""
.. module: lemur.sources.models
    :platform: unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy_utils import JSONType
from lemur.database import db

from lemur.plugins.base import plugins


class Source(db.Model):
    __tablename__ = 'sources'
    id = Column(Integer, primary_key=True)
    label = Column(String(32))
    options = Column(JSONType)
    description = Column(Text())
    plugin_name = Column(String(32))
    active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    endpoints = relationship("Endpoint", back_populates="source")

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return "Source(label={label})".format(label=self.label)
