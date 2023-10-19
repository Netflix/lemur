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

CertificateOwner = namedtuple("CertificateOwner", ["method", "value"])
CertificateOwnerNeed = partial(CertificateOwner, "role")


class SensitiveDomainPermission(Permission):
    def __init__(self):
        needs = [RoleNeed("admin")]
        sensitive_domain_roles = current_app.config.get("SENSITIVE_DOMAIN_ROLES", [])

        if sensitive_domain_roles:
            for role in sensitive_domain_roles:
                needs.append(RoleNeed(role))

        super().__init__(*needs)


class CertificatePermission(Permission):
    def __init__(self, owner, roles):
        needs = [RoleNeed("admin"), RoleNeed(owner), RoleNeed("creator")]
        for r in roles:
            needs.append(CertificateOwnerNeed(str(r)))
            # Backwards compatibility with mixed-case role names
            if str(r) != str(r).lower():
                needs.append(CertificateOwnerNeed(str(r).lower()))

        super().__init__(*needs)


class ApiKeyCreatorPermission(Permission):
    def __init__(self):
        super().__init__(RoleNeed("admin"))


RoleMember = namedtuple("RoleMember", ["method", "value"])
RoleMemberNeed = partial(RoleMember, "member")


class RoleMemberPermission(Permission):
    def __init__(self, role_id):
        needs = [RoleNeed("admin"), RoleMemberNeed(role_id)]
        super().__init__(*needs)


class AuthorityCreatorPermission(Permission):
    def __init__(self):
        requires_admin = current_app.config.get("ADMIN_ONLY_AUTHORITY_CREATION", False)
        if requires_admin:
            super().__init__(RoleNeed("admin"))
        else:
            super().__init__()


AuthorityCreator = namedtuple("AuthorityCreator", ["method", "value"])
AuthorityCreatorNeed = partial(AuthorityCreator, "authorityUse")

AuthorityOwner = namedtuple("AuthorityOwner", ["method", "value"])
AuthorityOwnerNeed = partial(AuthorityOwner, "role")


class AuthorityPermission(Permission):
    def __init__(self, authority_id, roles):
        needs = [RoleNeed("admin"), AuthorityCreatorNeed(str(authority_id))]
        for r in roles:
            needs.append(AuthorityOwnerNeed(str(r)))

        super().__init__(*needs)


class StrictRolePermission(Permission):
    def __init__(self):
        strict_role_enforcement = current_app.config.get("LEMUR_STRICT_ROLE_ENFORCEMENT", False)
        if strict_role_enforcement:
            needs = [RoleNeed("admin"), RoleNeed("operator")]
            super().__init__(*needs)
        else:
            super().__init__()
