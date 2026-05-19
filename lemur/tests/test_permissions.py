from unittest.mock import patch, MagicMock

from flask_principal import Identity, RoleNeed

from lemur.auth.permissions import StrictRolePermission, AuthorityCreatorPermission


def _config_get(overrides):
    """Returns a config.get side_effect function with the given key overrides."""
    def config_get(key, default=None):
        return overrides.get(key, default)
    return config_get


def _patch_config(overrides=None):
    mock_app = MagicMock()
    mock_app.config.get.side_effect = _config_get(overrides or {})
    return patch("lemur.auth.permissions.current_app", mock_app)


def _identity(*role_names):
    identity = Identity("test")
    for name in role_names:
        identity.provides.add(RoleNeed(name))
    return identity


class TestStrictRolePermission:
    def test_default_blocks_read_only(self):
        with _patch_config():
            perm = StrictRolePermission()
        assert not perm.allows(_identity("read-only"))

    def test_default_allows_admin(self):
        with _patch_config():
            perm = StrictRolePermission()
        assert perm.allows(_identity("admin"))

    def test_default_allows_operator(self):
        with _patch_config():
            perm = StrictRolePermission()
        assert perm.allows(_identity("operator"))

    def test_explicit_true_blocks_read_only(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}):
            perm = StrictRolePermission()
        assert not perm.allows(_identity("read-only"))

    def test_explicit_true_allows_admin(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}):
            perm = StrictRolePermission()
        assert perm.allows(_identity("admin"))

    def test_explicit_false_allows_read_only(self):
        """Explicit opt-in to open access must be preserved."""
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": False}):
            perm = StrictRolePermission()
        assert perm.allows(_identity("read-only"))


class TestAuthorityCreatorPermission:
    def test_default_blocks_read_only(self):
        with _patch_config():
            perm = AuthorityCreatorPermission()
        assert not perm.allows(_identity("read-only"))

    def test_default_allows_admin(self):
        with _patch_config():
            perm = AuthorityCreatorPermission()
        assert perm.allows(_identity("admin"))

    def test_explicit_true_blocks_read_only(self):
        with _patch_config({"ADMIN_ONLY_AUTHORITY_CREATION": True}):
            perm = AuthorityCreatorPermission()
        assert not perm.allows(_identity("read-only"))

    def test_explicit_true_allows_admin(self):
        with _patch_config({"ADMIN_ONLY_AUTHORITY_CREATION": True}):
            perm = AuthorityCreatorPermission()
        assert perm.allows(_identity("admin"))

    def test_explicit_false_allows_read_only(self):
        """Explicit opt-in to open access must be preserved."""
        with _patch_config({"ADMIN_ONLY_AUTHORITY_CREATION": False}):
            perm = AuthorityCreatorPermission()
        assert perm.allows(_identity("read-only"))
