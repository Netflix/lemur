"""
.. module: lemur.logs.models
    :platform: unix
    :synopsis: This module contains all of the models related private key audit log.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from sqlalchemy import Column, Integer, ForeignKey, DefaultClause, func, Enum

from sqlalchemy_utils.types.arrow import ArrowType

from lemur.database import BaseModel


class Log(BaseModel):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"))
    log_type = Column(
        Enum(
            "key_view",
            "create_cert",
            "update_cert",
            "revoke_cert",
            "delete_cert",
            name="log_type",
        ),
        nullable=False,
    )
    logged_at = Column(ArrowType(), DefaultClause(func.now()), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
