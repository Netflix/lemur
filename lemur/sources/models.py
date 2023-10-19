"""
.. module: lemur.sources.models
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Text, Boolean
from sqlalchemy_utils import JSONType
from lemur.database import BaseModel

from lemur.plugins.base import plugins
from sqlalchemy_utils import ArrowType


class Source(BaseModel):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    label = Column(String(32), unique=True)
    options = Column(JSONType)
    description = Column(Text())
    plugin_name = Column(String(32))
    active = Column(Boolean, default=True)
    last_run = Column(ArrowType)
    endpoints = relationship("Endpoint", back_populates="source")

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return f"Source(label={self.label})"
