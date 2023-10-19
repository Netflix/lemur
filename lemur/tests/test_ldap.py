import pytest
from lemur.auth.ldap import *  # noqa
from unittest.mock import patch, MagicMock


class LdapPrincipalTester(LdapPrincipal):
    def __init__(self, args):
        super().__init__(args)
        self.ldap_server = "ldap://localhost"

    def bind_test(self):
        groups = [
            (
                "user",
                {
                    "memberOf": [
                        b"CN=Lemur Access,OU=Groups,DC=example,DC=com",
                        b"CN=Pen Pushers,OU=Groups,DC=example,DC=com",
                    ]
                },
            )
        ]
        self.ldap_client = MagicMock()
        self.ldap_client.search_s.return_value = groups
        self._bind()

    def authorize_test_groups_to_roles_admin(self):
        self.ldap_groups = "".join(
            [
                "CN=Pen Pushers,OU=Groups,DC=example,DC=com",
                "CN=Lemur Admins,OU=Groups,DC=example,DC=com",
                "CN=Lemur Read Only,OU=Groups,DC=example,DC=com",
            ]
        )
        self.ldap_required_group = None
        self.ldap_groups_to_roles = {
            "Lemur Admins": "admin",
            "Lemur Read Only": "read-only",
        }
        return self._authorize()

    def authorize_test_required_group(self, group):
        self.ldap_groups = "".join(
            [
                "CN=Lemur Access,OU=Groups,DC=example,DC=com",
                "CN=Pen Pushers,OU=Groups,DC=example,DC=com",
            ]
        )
        self.ldap_required_group = group
        return self._authorize()


@pytest.fixture()
def principal(session):
    args = {"username": "user", "password": "p4ssw0rd"}
    yield LdapPrincipalTester(args)


class TestLdapPrincipal:
    @patch("ldap.initialize")
    def test_bind(self, app, principal):
        self.test_ldap_user = principal
        self.test_ldap_user.bind_test()
        group = "Pen Pushers"
        assert group in self.test_ldap_user.ldap_groups
        assert self.test_ldap_user.ldap_principal == "user@example.com"

    def test_authorize_groups_to_roles_admin(self, app, principal):
        self.test_ldap_user = principal
        roles = self.test_ldap_user.authorize_test_groups_to_roles_admin()
        assert any(x.name == "admin" for x in roles)

    def test_authorize_required_group_missing(self, app, principal):
        self.test_ldap_user = principal
        roles = self.test_ldap_user.authorize_test_required_group("Not Allowed")
        assert not roles

    def test_authorize_required_group_access(self, session, principal):
        self.test_ldap_user = principal
        roles = self.test_ldap_user.authorize_test_required_group("Lemur Access")
        assert len(roles) >= 1
        assert any(x.name == "user@example.com" for x in roles)
