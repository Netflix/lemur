"""
.. module: lemur.api_keys.models
    :platform: Unix
    :synopsis: This module contains all of the models need to create an api key within Lemur.
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Eric Coan <kungfury@instructure.com>
"""
from sqlalchemy import BigInteger, Boolean, Column, ForeignKey, Integer, String

from lemur.database import BaseModel


class ApiKey(BaseModel):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    ttl = Column(BigInteger)
    issued_at = Column(BigInteger)
    revoked = Column(Boolean)
    application_name = Column(String, nullable=True)

    def __repr__(self):
        return "ApiKey(name={name}, user_id={user_id}, ttl={ttl}, issued_at={iat}, revoked={revoked})".format(
            user_id=self.user_id,
            name=self.name,
            ttl=self.ttl,
            iat=self.issued_at,
            revoked=self.revoked,
        )
