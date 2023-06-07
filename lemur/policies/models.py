"""
.. module: lemur.policies.models
    :platform: unix
    :synopsis: This module contains all of the models need to create a certificate policy within Lemur.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, String

from lemur.database import BaseModel


class RotationPolicy(BaseModel):
    __tablename__ = "rotation_policies"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    days = Column(Integer)

    def __repr__(self):
        return "RotationPolicy(days={days}, name={name})".format(
            days=self.days, name=self.name
        )
