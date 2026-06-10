from unittest.mock import MagicMock, patch

from lemur.users import service as user_service


def _role(name):
    r = MagicMock()
    r.name = name
    return r


def _patch_config(overrides=None):
    mock_app = MagicMock()

    def config_get(key, default=None):
        return (overrides or {}).get(key, default)
    mock_app.config.get.side_effect = config_get
    return patch("lemur.users.service.current_app", mock_app)


class TestCreateStrictRoleEnforcement:
    def test_default_allows_user_with_no_default_role(self):
        with _patch_config(), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("custom")])
        mock_create.assert_called_once()

    def test_default_allows_user_with_admin_role(self):
        with _patch_config(), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("admin")])
        mock_create.assert_called_once()

    def test_explicit_true_blocks_user_with_no_default_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}):
            result = user_service.create("alice", "pass", "a@x.com", True, "", [_role("custom")])
        assert isinstance(result, tuple)
        error, status = result
        assert status == 400
        assert "LEMUR_STRICT_ROLE_ENFORCEMENT" in error["message"]

    def test_explicit_true_allows_user_with_admin_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("admin")])
        mock_create.assert_called_once()

    def test_explicit_true_allows_user_with_operator_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("operator")])
        mock_create.assert_called_once()

    def test_explicit_true_allows_user_with_read_only_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("read-only")])
        mock_create.assert_called_once()

    def test_explicit_false_allows_user_with_no_default_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": False}), \
             patch("lemur.users.service.database.create") as mock_create, \
             patch("lemur.users.service.log_service.audit_log"):
            mock_create.return_value = MagicMock()
            user_service.create("alice", "pass", "a@x.com", True, "", [_role("custom")])
        mock_create.assert_called_once()


class TestUpdateStrictRoleEnforcement:
    def test_default_allows_user_with_no_default_role(self):
        with _patch_config(), \
             patch("lemur.users.service.get") as mock_get, \
             patch("lemur.users.service.database.update") as mock_update, \
             patch("lemur.users.service.update_roles"), \
             patch("lemur.users.service.log_service.audit_log"):
            mock_get.return_value = MagicMock()
            mock_update.return_value = MagicMock()
            user_service.update(1, "alice", "a@x.com", True, "", [_role("custom")])
        mock_update.assert_called_once()

    def test_explicit_true_blocks_user_with_no_default_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": True}):
            result = user_service.update(1, "alice", "a@x.com", True, "", [_role("custom")])
        assert isinstance(result, tuple)
        error, status = result
        assert status == 400
        assert "LEMUR_STRICT_ROLE_ENFORCEMENT" in error["message"]

    def test_explicit_false_allows_user_with_no_default_role(self):
        with _patch_config({"LEMUR_STRICT_ROLE_ENFORCEMENT": False}), \
             patch("lemur.users.service.get") as mock_get, \
             patch("lemur.users.service.database.update") as mock_update, \
             patch("lemur.users.service.update_roles"), \
             patch("lemur.users.service.log_service.audit_log"):
            mock_get.return_value = MagicMock()
            mock_update.return_value = MagicMock()
            user_service.update(1, "alice", "a@x.com", True, "", [_role("custom")])
        mock_update.assert_called_once()
