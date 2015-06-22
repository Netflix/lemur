"""
.. module: lemur.models
    :platform: Unix
    :synopsis: This module contains all of the associative tables
    that help define the many to many relationships established in Lemur

    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from sqlalchemy import Column, Integer, ForeignKey

from lemur.database import db

certificate_associations = db.Table('certificate_associations',
    Column('domain_id', Integer, ForeignKey('domains.id')),
    Column('certificate_id', Integer, ForeignKey('certificates.id'))
)

certificate_account_associations = db.Table('certificate_account_associations',
    Column('account_id', Integer, ForeignKey('accounts.id', ondelete='cascade')),
    Column('certificate_id', Integer, ForeignKey('certificates.id', ondelete='cascade'))
)

roles_users = db.Table('roles_users',
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

