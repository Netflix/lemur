"""
.. module: permissions
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
CertificateCreatorNeed = partial(CertificateCreator, 'certificateView')

CertificateOwner = namedtuple('certificate', ['method', 'value'])
CertificateOwnerNeed = partial(CertificateOwner, 'certificateView')


class ViewKeyPermission(Permission):
    def __init__(self, role_id, certificate_id):
        c_need = CertificateCreatorNeed(unicode(certificate_id))
        o_need = CertificateOwnerNeed(unicode(role_id))
        super(ViewKeyPermission, self).__init__(o_need, c_need, RoleNeed('admin'))


class UpdateCertificatePermission(Permission):
    def __init__(self, role_id, certificate_id):
        c_need = CertificateCreatorNeed(unicode(certificate_id))
        o_need = CertificateOwnerNeed(unicode(role_id))
        super(UpdateCertificatePermission, self).__init__(o_need, c_need, RoleNeed('admin'))


RoleUser = namedtuple('role', ['method', 'value'])
ViewRoleCredentialsNeed = partial(RoleUser, 'roleView')


class ViewRoleCredentialsPermission(Permission):
    def __init__(self, role_id):
        need = ViewRoleCredentialsNeed(unicode(role_id))
        super(ViewRoleCredentialsPermission, self).__init__(need, RoleNeed('admin'))


AuthorityCreator = namedtuple('authority', ['method', 'value'])
AuthorityCreatorNeed = partial(AuthorityCreator, 'authorityUse')

AuthorityOwner = namedtuple('authority', ['method', 'value'])
AuthorityOwnerNeed = partial(AuthorityOwner, 'role')


class AuthorityPermission(Permission):
    def __init__(self, authority_id, roles):
        needs = [RoleNeed('admin'), AuthorityCreatorNeed(unicode(authority_id))]
        for r in roles:
            needs.append(AuthorityOwnerNeed(unicode(r)))

        super(AuthorityPermission, self).__init__(*needs)
