"""
.. module: lemur.certificates.models
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
import datetime

from flask import current_app

from sqlalchemy import event, Integer, ForeignKey, String, DateTime, PassiveDefault, func, Column, Text, Boolean
from sqlalchemy.orm import relationship

from lemur.database import db
from lemur.models import certificate_associations, certificate_source_associations, \
    certificate_destination_associations, certificate_notification_associations, \
    certificate_replacement_associations, roles_certificates
from lemur.plugins.base import plugins
from lemur.utils import Vault

from lemur.common import defaults
from lemur.domains.models import Domain


def get_or_increase_name(name):
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
    active = Column(Boolean, default=True)

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
    authority_id = Column(Integer, ForeignKey('authorities.id'))
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

    def __init__(self, **kwargs):
        cert = defaults.parse_certificate(kwargs['body'])
        self.owner = kwargs['owner']
        self.body = kwargs['body']
        self.private_key = kwargs.get('private_key')
        self.chain = kwargs.get('chain')
        self.destinations = kwargs.get('destinations', [])
        self.notifications = kwargs.get('notifications', [])
        self.description = kwargs.get('description')
        self.roles = kwargs.get('roles', [])
        self.replaces = kwargs.get('replacements', [])
        self.signing_algorithm = defaults.signing_algorithm(cert)
        self.bits = defaults.bitstrength(cert)
        self.issuer = defaults.issuer(cert)
        self.serial = defaults.serial(cert)
        self.cn = defaults.common_name(cert)
        self.san = defaults.san(cert)
        self.not_before = defaults.not_before(cert)
        self.not_after = defaults.not_after(cert)
        self.name = get_or_increase_name(defaults.certificate_name(self.cn, self.issuer, self.not_before, self.not_after, self.san))

        for domain in defaults.domains(cert):
            self.domains.append(Domain(name=domain))

    @property
    def is_expired(self):
        if self.not_after < datetime.datetime.now():
            return True

    @property
    def is_unused(self):
        if self.elb_listeners.count() == 0:
            return True

    @property
    def is_revoked(self):
        # we might not yet know the condition of the cert
        if self.status:
            if 'revoked' in self.status:
                return True

    def get_arn(self, account_number):
        """
        Generate a valid AWS IAM arn

        :rtype : str
        :param account_number:
        :return:
        """
        return "arn:aws:iam::{}:server-certificate/{}".format(account_number, self.name)


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
    When a certificate is marked as 'replaced' it is then marked as in-active

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    value.active = False


@event.listens_for(Certificate, 'before_update')
def protect_active(mapper, connection, target):
    """
    When a certificate has a replacement do not allow it to be marked as 'active'

    :param connection:
    :param mapper:
    :param target:
    :return:
    """
    if target.active:
        if target.replaced:
            raise Exception("Cannot mark certificate as active, certificate has been marked as replaced.")
