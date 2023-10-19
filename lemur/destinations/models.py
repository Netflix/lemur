"""
.. module: lemur.destinations.models
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import validates
from sqlalchemy_utils import JSONType
from lemur.database import BaseModel

from lemur.plugins.base import plugins


class Destination(BaseModel):
    __tablename__ = "destinations"
    id = Column(Integer, primary_key=True)
    label = Column(String(32))
    options = Column(JSONType)
    description = Column(Text())
    plugin_name = Column(String(32))

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    @validates("label")
    def validate_label(self, key, label):
        if len(label) > 32:
            raise ValueError("Label exceeds max length of 32")
        return label

    def __repr__(self):
        return f"Destination(label={self.label})"
