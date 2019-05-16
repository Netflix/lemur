"""
.. module: lemur.domains.models
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""
from sqlalchemy import Column, Integer, String, Boolean, Index

from lemur.database import db


class Domain(db.Model):
    __tablename__ = "domains"
    __table_args__ = (
        Index(
            "ix_domains_name_gin",
            "name",
            postgresql_ops={"name": "gin_trgm_ops"},
            postgresql_using="gin",
        ),
    )
    id = Column(Integer, primary_key=True)
    name = Column(String(256), index=True)
    sensitive = Column(Boolean, default=False)

    def __repr__(self):
        return "Domain(name={name})".format(name=self.name)
