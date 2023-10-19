"""
.. module: lemur.authorizations.models
    :platform: unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Netflix Secops <secops@netflix.com>
"""
from sqlalchemy import Column, Integer, String
from sqlalchemy_utils import JSONType
from lemur.database import BaseModel

from lemur.plugins.base import plugins


class Authorization(BaseModel):
    __tablename__ = "pending_dns_authorizations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_number = Column(String(128))
    domains = Column(JSONType)
    dns_provider_type = Column(String(128))
    options = Column(JSONType)

    @property
    def plugin(self):
        return plugins.get(self.plugin_name)

    def __repr__(self):
        return f"Authorization(id={self.id})"

    def __init__(self, account_number, domains, dns_provider_type, options=None):
        self.account_number = account_number
        self.domains = domains
        self.dns_provider_type = dns_provider_type
        self.options = options
