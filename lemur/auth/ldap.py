"""
.. module: lemur.auth.ldap
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Ian Stahnke <ian.stahnke@myob.com>
"""
import ldap
from flask import current_app

from lemur.common.utils import validate_conf, get_psuedo_random_string
from lemur.roles import service as role_service
from lemur.users import service as user_service


class LdapPrincipal:
    """
    Provides methods for authenticating against an LDAP server.
    """

    def __init__(self, args):
        self._ldap_validate_conf()
        # setup ldap config
        if not args["username"]:
            raise Exception("missing ldap username")
        if not args["password"]:
            self.error_message = "missing ldap password"
            raise Exception("missing ldap password")
        self.ldap_principal = args["username"]
        self.ldap_email_domain = current_app.config.get("LDAP_EMAIL_DOMAIN", None)
        if "@" not in self.ldap_principal:
            self.ldap_principal = "{}@{}".format(
                self.ldap_principal,
                self.ldap_email_domain,
            )
        self.ldap_username = args["username"]
        if "@" in self.ldap_username:
            self.ldap_username = args["username"].split("@")[0]
        self.ldap_password = args["password"]
        self.ldap_server = current_app.config.get("LDAP_BIND_URI", None)
        self.ldap_base_dn = current_app.config.get("LDAP_BASE_DN", None)
        self.ldap_use_tls = current_app.config.get("LDAP_USE_TLS", False)
        self.ldap_cacert_file = current_app.config.get("LDAP_CACERT_FILE", None)
        self.ldap_default_role = current_app.config.get("LEMUR_DEFAULT_ROLE", None)
        self.ldap_required_group = current_app.config.get("LDAP_REQUIRED_GROUP", None)
        self.ldap_groups_to_roles = current_app.config.get("LDAP_GROUPS_TO_ROLES", None)
        self.ldap_is_active_directory = current_app.config.get(
            "LDAP_IS_ACTIVE_DIRECTORY", False
        )
        self.ldap_attrs = ["memberOf"]
        self.ldap_client = None
        self.ldap_groups = None

    def _update_user(self, roles):
        """
        create or update a local user instance.
        """
        # try to get user from local database
        user = user_service.get_by_email(self.ldap_principal)

        # create them a local account
        if not user:
            user = user_service.create(
                self.ldap_username,
                get_psuedo_random_string(),
                self.ldap_principal,
                True,
                "",  # thumbnailPhotoUrl
                list(roles),
            )
        else:
            # we add 'lemur' specific roles, so they do not get marked as removed
            for ur in user.roles:
                if not ur.third_party:
                    roles.add(ur)

            # update any changes to the user
            user_service.update(
                user.id,
                self.ldap_username,
                self.ldap_principal,
                user.active,
                user.profile_picture,
                list(roles),
            )
        return user

    def _authorize(self):
        """
        check groups and roles to confirm access.
        return a list of roles if ok.
        raise an exception on error.
        """
        if not self.ldap_principal:
            return None

        if self.ldap_required_group:
            # ensure the user has the required group in their group list
            if self.ldap_required_group not in self.ldap_groups:
                return None

        roles = set()
        if self.ldap_default_role:
            role = role_service.get_by_name(self.ldap_default_role)
            if role:
                if not role.third_party:
                    role = role_service.set_third_party(role.id, third_party_status=True)
                roles.add(role)

        # update their 'roles'
        role = role_service.get_by_name(self.ldap_principal)
        if not role:
            description = "auto generated role based on owner: {}".format(
                self.ldap_principal
            )
            role = role_service.create(
                self.ldap_principal, description=description, third_party=True
            )
        if not role.third_party:
            role = role_service.set_third_party(role.id, third_party_status=True)
        roles.add(role)
        if not self.ldap_groups_to_roles:
            return roles

        for ldap_group_name, role_name in self.ldap_groups_to_roles.items():
            role = role_service.get_by_name(role_name)
            if role:
                if ldap_group_name in self.ldap_groups:
                    current_app.logger.debug(
                        "assigning role {} to ldap user {}".format(
                            self.ldap_principal, role
                        )
                    )
                    if not role.third_party:
                        role = role_service.set_third_party(
                            role.id, third_party_status=True
                        )
                    roles.add(role)
        return roles

    def authenticate(self):
        """
        orchestrate the ldap login.
        raise an exception on error.
        """
        self._bind()
        roles = self._authorize()
        if not roles:
            raise Exception("ldap authorization failed")
        return self._update_user(roles)

    def _bind(self):
        """
        authenticate an ldap user.
        list groups for a user.
        raise an exception on error.
        """
        if "@" not in self.ldap_principal:
            self.ldap_principal = "{}@{}".format(
                self.ldap_principal,
                self.ldap_email_domain,
            )
        ldap_filter = "userPrincipalName=%s" % self.ldap_principal

        # query ldap for auth
        try:
            # build a client
            if not self.ldap_client:
                self.ldap_client = ldap.initialize(self.ldap_server)
            # perform a synchronous bind
            self.ldap_client.set_option(ldap.OPT_REFERRALS, 0)
            if self.ldap_use_tls:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                self.ldap_client.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                self.ldap_client.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
                self.ldap_client.set_option(ldap.OPT_X_TLS_DEMAND, True)
                self.ldap_client.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            if self.ldap_cacert_file:
                self.ldap_client.set_option(
                    ldap.OPT_X_TLS_CACERTFILE, self.ldap_cacert_file
                )
            self.ldap_client.simple_bind_s(self.ldap_principal, self.ldap_password)
        except ldap.INVALID_CREDENTIALS:
            self.ldap_client.unbind()
            raise Exception("The supplied ldap credentials are invalid")
        except ldap.SERVER_DOWN:
            raise Exception("ldap server unavailable")
        except ldap.LDAPError as e:
            raise Exception(f"ldap error: {e}")

        if self.ldap_is_active_directory:
            # Lookup user DN, needed to search for group membership
            userdn = self.ldap_client.search_s(
                self.ldap_base_dn,
                ldap.SCOPE_SUBTREE,
                ldap_filter,
                ["distinguishedName"],
            )[0][1]["distinguishedName"][0]
            userdn = userdn.decode("utf-8")
            # Search all groups that have the userDN as a member
            groupfilter = "(&(objectclass=group)(member:1.2.840.113556.1.4.1941:={}))".format(
                userdn
            )
            lgroups = self.ldap_client.search_s(
                self.ldap_base_dn, ldap.SCOPE_SUBTREE, groupfilter, ["cn"]
            )

            # Create a list of group CN's from the result
            self.ldap_groups = []
            for group in lgroups:
                (dn, values) = group
                if isinstance(values, dict):
                    self.ldap_groups.append(values["cn"][0].decode("utf-8"))
        else:
            lgroups = self.ldap_client.search_s(
                self.ldap_base_dn, ldap.SCOPE_SUBTREE, ldap_filter, self.ldap_attrs
            )[0][1]["memberOf"]
            # lgroups is a list of utf-8 encoded strings
            # convert to a single string of groups to allow matching
            self.ldap_groups = b"".join(lgroups).decode("ascii")

        self.ldap_client.unbind()

    def _ldap_validate_conf(self):
        """
        Confirms required ldap config settings exist.
        """
        required_vars = ["LDAP_BIND_URI", "LDAP_BASE_DN", "LDAP_EMAIL_DOMAIN"]
        validate_conf(current_app, required_vars)
