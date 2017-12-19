"""
.. module: lemur.pending_certificates.models
    Copyright (c) 2017 and onwards Instart Logic, Inc.  All rights reserved.
.. moduleauthor:: James Chuong <jchuong@instartlogic.com>
"""
from datetime import datetime as dt

from sqlalchemy.orm import relationship
from sqlalchemy import Integer, ForeignKey, String, PassiveDefault, func, Column, Text, Boolean
from sqlalchemy_utils.types.arrow import ArrowType

from lemur.certificates.models import get_or_increase_name
from lemur.common import defaults
from lemur.database import db
from lemur.utils import Vault

from lemur.models import pending_cert_source_associations, \
    pending_cert_destination_associations, pending_cert_notification_associations, \
    pending_cert_replacement_associations, pending_cert_role_associations


class PendingCertificate(db.Model):
    __tablename__ = 'pending_certs'
    id = Column(Integer, primary_key=True)
    external_id = Column(String(128))
    owner = Column(String(128), nullable=False)
    name = Column(String(256), unique=True)
    description = Column(String(1024))
    notify = Column(Boolean, default=True)
    number_attempts = Column(Integer)
    rename = Column(Boolean, default=True)

    csr = Column(Text(), nullable=False)
    chain = Column(Text())
    private_key = Column(Vault, nullable=True)

    date_created = Column(ArrowType, PassiveDefault(func.now()), nullable=False)

    status = Column(String(128))

    rotation = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    authority_id = Column(Integer, ForeignKey('authorities.id', ondelete="CASCADE"))
    root_authority_id = Column(Integer, ForeignKey('authorities.id', ondelete="CASCADE"))
    rotation_policy_id = Column(Integer, ForeignKey('rotation_policies.id'))

    notifications = relationship('Notification', secondary=pending_cert_notification_associations, backref='pending_cert', passive_deletes=True)
    destinations = relationship('Destination', secondary=pending_cert_destination_associations, backref='pending_cert', passive_deletes=True)
    sources = relationship('Source', secondary=pending_cert_source_associations, backref='pending_cert', passive_deletes=True)
    roles = relationship('Role', secondary=pending_cert_role_associations, backref='pending_cert', passive_deletes=True)
    replaces = relationship('Certificate',
                            secondary=pending_cert_replacement_associations,
                            primaryjoin=id == pending_cert_replacement_associations.c.pending_cert_id,  # noqa
                            secondaryjoin=id == pending_cert_replacement_associations.c.replaced_certificate_id,  # noqa
                            backref='pending_cert',
                            viewonly=True)

    rotation_policy = relationship("RotationPolicy")

    sensitive_fields = ('private_key',)

    def __init__(self, **kwargs):
        self.csr = kwargs.get('csr')
        self.private_key = kwargs.get('private_key', "")
        if self.private_key:
            # If the request does not send private key, the key exists but the value is None
            self.private_key = self.private_key.strip()
        self.external_id = kwargs.get('external_id')

        # when destinations are appended they require a valid name.
        if kwargs.get('name'):
            self.name = get_or_increase_name(defaults.text_to_slug(kwargs['name']), 0)
            self.rename = False
        else:
            # TODO: Fix auto-generated name, it should be renamed on creation
            self.name = get_or_increase_name(
                defaults.certificate_name(kwargs['common_name'], kwargs['authority'].name,
                    dt.now(), dt.now(), False), self.external_id)
            self.rename = True

        self.owner = kwargs['owner']
        self.number_attempts = 0

        if kwargs.get('chain'):
            self.chain = kwargs['chain'].strip()

        self.notify = kwargs.get('notify', True)
        self.destinations = kwargs.get('destinations', [])
        self.notifications = kwargs.get('notifications', [])
        self.description = kwargs.get('description')
        self.roles = list(set(kwargs.get('roles', [])))
        self.replaces = kwargs.get('replaces', [])
        self.rotation = kwargs.get('rotation')
        self.rotation_policy = kwargs.get('rotation_policy')
