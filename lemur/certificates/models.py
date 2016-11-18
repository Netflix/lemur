"""
.. module: lemur.certificates.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import datetime

import lemur.common.utils
from flask import current_app

from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import case
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import event, Integer, ForeignKey, String, DateTime, PassiveDefault, func, Column, Text, Boolean

from lemur.database import db
from lemur.models import certificate_associations, certificate_source_associations, \
    certificate_destination_associations, certificate_notification_associations, \
    certificate_replacement_associations, roles_certificates
from lemur.plugins.base import plugins
from lemur.utils import Vault

from lemur.common import defaults
from lemur.domains.models import Domain


def get_or_increase_name(name):
    name = '-'.join(name.strip().split(' '))
    count = Certificate.query.filter(Certificate.name.ilike('{0}%'.format(name))).count()

    if count >= 1:
        return name + '-' + str(count)

    return name


class Certificate(db.Model):
    __tablename__ = 'certificates'
    id = Column(Integer, primary_key=True)
    owner = Column(String(128), nullable=False)
    name = Column(String(128), unique=True)
    description = Column(String(1024))
    notify = Column(Boolean, default=True)

    body = Column(Text(), nullable=False)
    chain = Column(Text())
    private_key = Column(Vault)

    issuer = Column(String(128))
    serial = Column(String(128))
    cn = Column(String(128))
    deleted = Column(Boolean, index=True)

    not_before = Column(DateTime)
    not_after = Column(DateTime)
    date_created = Column(DateTime, PassiveDefault(func.now()), nullable=False)

    signing_algorithm = Column(String(128))
    status = Column(String(128))
    bits = Column(Integer())
    san = Column(String(1024))  # TODO this should be migrated to boolean

    user_id = Column(Integer, ForeignKey('users.id'))
    authority_id = Column(Integer, ForeignKey('authorities.id', ondelete="CASCADE"))
    root_authority_id = Column(Integer, ForeignKey('authorities.id', ondelete="CASCADE"))

    notifications = relationship("Notification", secondary=certificate_notification_associations, backref='certificate')
    destinations = relationship("Destination", secondary=certificate_destination_associations, backref='certificate')
    sources = relationship("Source", secondary=certificate_source_associations, backref='certificate')
    domains = relationship("Domain", secondary=certificate_associations, backref="certificate")
    roles = relationship("Role", secondary=roles_certificates, backref="certificate")
    replaces = relationship("Certificate",
                            secondary=certificate_replacement_associations,
                            primaryjoin=id == certificate_replacement_associations.c.certificate_id,  # noqa
                            secondaryjoin=id == certificate_replacement_associations.c.replaced_certificate_id,  # noqa
                            backref='replaced')

    endpoints = relationship("Endpoint", backref='certificate')

    def __init__(self, **kwargs):
        cert = lemur.common.utils.parse_certificate(kwargs['body'])

        self.issuer = defaults.issuer(cert)
        self.cn = defaults.common_name(cert)
        self.san = defaults.san(cert)
        self.not_before = defaults.not_before(cert)
        self.not_after = defaults.not_after(cert)

        # when destinations are appended they require a valid name.
        if kwargs.get('name'):
            self.name = get_or_increase_name(kwargs['name'])
        else:
            self.name = get_or_increase_name(defaults.certificate_name(self.cn, self.issuer, self.not_before, self.not_after, self.san))

        self.owner = kwargs['owner']
        self.body = kwargs['body'].strip()

        if kwargs.get('private_key'):
            self.private_key = kwargs['private_key'].strip()

        if kwargs.get('chain'):
            self.chain = kwargs['chain'].strip()

        self.notify = kwargs.get('notify', True)
        self.destinations = kwargs.get('destinations', [])
        self.notifications = kwargs.get('notifications', [])
        self.description = kwargs.get('description')
        self.roles = list(set(kwargs.get('roles', [])))
        self.replaces = kwargs.get('replacements', [])
        self.signing_algorithm = defaults.signing_algorithm(cert)
        self.bits = defaults.bitstrength(cert)
        self.serial = defaults.serial(cert)

        for domain in defaults.domains(cert):
            self.domains.append(Domain(name=domain))

    @property
    def active(self):
        return self.notify

    @hybrid_property
    def expired(self):
        if self.not_after <= datetime.datetime.now():
            return True

    @expired.expression
    def expired(cls):
        return case(
            [
                (cls.now_after <= datetime.datetime.now(), True)
            ],
            else_=False
        )

    @hybrid_property
    def revoked(self):
        if 'revoked' == self.status:
            return True

    @revoked.expression
    def revoked(cls):
        return case(
            [
                (cls.status == 'revoked', True)
            ],
            else_=False
        )

    @property
    def extensions(self):
        # TODO pull the OU, O, CN, etc + other extensions.
        names = [{'name_type': 'DNSName', 'value': x.name} for x in self.domains]

        extensions = {
            'sub_alt_names': {
                'names': names
            }
        }

        return extensions

    def get_arn(self, account_number):
        """
        Generate a valid AWS IAM arn

        :rtype : str
        :param account_number:
        :return:
        """
        return "arn:aws:iam::{}:server-certificate/{}".format(account_number, self.name)

    def __repr__(self):
        return "Certificate(name={name})".format(name=self.name)


@event.listens_for(Certificate.destinations, 'append')
def update_destinations(target, value, initiator):
    """
    Attempt to upload the new certificate to the new destination

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    destination_plugin = plugins.get(value.plugin_name)

    try:
        destination_plugin.upload(target.name, target.body, target.private_key, target.chain, value.options)
    except Exception as e:
        current_app.logger.exception(e)


@event.listens_for(Certificate.replaces, 'append')
def update_replacement(target, value, initiator):
    """
    When a certificate is marked as 'replaced' we should not notify.

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    value.notify = False


# @event.listens_for(Certificate, 'before_update')
# def protect_active(mapper, connection, target):
#    """
#     When a certificate has a replacement do not allow it to be marked as 'active'
#
#     :param connection:
#     :param mapper:
#     :param target:
#     :return:
#     """
#     if target.active:
#         if not target.notify:
#             raise Exception(
#                 "Cannot silence notification for a certificate Lemur has been found to be currently deployed onto endpoints"
#             )
