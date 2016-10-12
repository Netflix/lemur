"""
.. module: lemur.auth.permissions
    :platform: Unix
    :synopsis: This module defines all the permission used within Lemur
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from functools import partial
from collections import namedtuple

from flask.ext.principal import Permission, RoleNeed

# Permissions
operator_permission = Permission(RoleNeed('operator'))
admin_permission = Permission(RoleNeed('admin'))

CertificateCreator = namedtuple('certificate', ['method', 'value'])
CertificateCreatorNeed = partial(CertificateCreator, 'key')

CertificateOwner = namedtuple('certificate', ['method', 'value'])
CertificateOwnerNeed = partial(CertificateOwner, 'role')


class SensitiveDomainPermission(Permission):
    def __init__(self):
        super(SensitiveDomainPermission, self).__init__(RoleNeed('admin'))


class CertificatePermission(Permission):
    def __init__(self, certificate_id, owner, roles):
        needs = [RoleNeed('admin'), CertificateCreatorNeed(certificate_id), RoleNeed(owner)]
        for r in roles:
            needs.append(CertificateOwnerNeed(str(r)))

        super(CertificatePermission, self).__init__(*needs)


RoleMember = namedtuple('role', ['method', 'value'])
RoleMemberNeed = partial(RoleMember, 'member')


class RoleMemberPermission(Permission):
    def __init__(self, role_id):
        needs = [RoleNeed('admin'), RoleMemberNeed(role_id)]
        super(RoleMemberPermission, self).__init__(*needs)


AuthorityCreator = namedtuple('authority', ['method', 'value'])
AuthorityCreatorNeed = partial(AuthorityCreator, 'authorityUse')

AuthorityOwner = namedtuple('authority', ['method', 'value'])
AuthorityOwnerNeed = partial(AuthorityOwner, 'role')


class AuthorityPermission(Permission):
    def __init__(self, authority_id, roles):
        needs = [RoleNeed('admin'), AuthorityCreatorNeed(str(authority_id))]
        for r in roles:
            needs.append(AuthorityOwnerNeed(str(r)))

        super(AuthorityPermission, self).__init__(*needs)
