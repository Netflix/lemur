"""
.. module: lemur.destinations.models
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy_utils import JSONType
from lemur.database import db

from lemur.plugins.base import plugins


class Destination(db.Model):
    __tablename__ = "destinations"
    id = Column(Integer, primary_key=True)
    label = Column(String(32))
    options = Column(JSONType)
    description = Column(Text())
    plugin_name = Column(String(32))

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return "Destination(label={label})".format(label=self.label)
