"""
.. module: lemur.auth.permissions
    :platform: Unix
    :synopsis: This module defines all the permission used within Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""
from functools import partial
from collections import namedtuple

from flask import current_app
from flask_principal import Permission, RoleNeed

# Permissions
operator_permission = Permission(RoleNeed("operator"))
admin_permission = Permission(RoleNeed("admin"))

CertificateOwner = namedtuple("certificate", ["method", "value"])
CertificateOwnerNeed = partial(CertificateOwner, "role")


class SensitiveDomainPermission(Permission):
    def __init__(self):
        needs = [RoleNeed("admin")]
        sensitive_domain_roles = current_app.config.get("SENSITIVE_DOMAIN_ROLES", [])

        if sensitive_domain_roles:
            for role in sensitive_domain_roles:
                needs.append(RoleNeed(role))

        super(SensitiveDomainPermission, self).__init__(*needs)


class CertificatePermission(Permission):
    def __init__(self, owner, roles):
        needs = [RoleNeed("admin"), RoleNeed(owner), RoleNeed("creator")]
        for r in roles:
            needs.append(CertificateOwnerNeed(str(r)))
            # Backwards compatibility with mixed-case role names
            if str(r) != str(r).lower():
                needs.append(CertificateOwnerNeed(str(r).lower()))

        super(CertificatePermission, self).__init__(*needs)


class ApiKeyCreatorPermission(Permission):
    def __init__(self):
        super(ApiKeyCreatorPermission, self).__init__(RoleNeed("admin"))


RoleMember = namedtuple("role", ["method", "value"])
RoleMemberNeed = partial(RoleMember, "member")


class RoleMemberPermission(Permission):
    def __init__(self, role_id):
        needs = [RoleNeed("admin"), RoleMemberNeed(role_id)]
        super(RoleMemberPermission, self).__init__(*needs)


AuthorityCreator = namedtuple("authority", ["method", "value"])
AuthorityCreatorNeed = partial(AuthorityCreator, "authorityUse")

AuthorityOwner = namedtuple("authority", ["method", "value"])
AuthorityOwnerNeed = partial(AuthorityOwner, "role")


class AuthorityPermission(Permission):
    def __init__(self, authority_id, roles):
        needs = [RoleNeed("admin"), AuthorityCreatorNeed(str(authority_id))]
        for r in roles:
            needs.append(AuthorityOwnerNeed(str(r)))

        super(AuthorityPermission, self).__init__(*needs)
