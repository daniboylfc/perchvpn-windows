"""Rebrand continuity: the stranded FoxyVPN token store migrates forward.

Yesterday's helper sign-in persisted %APPDATA%/FoxyVPN/tokens.json; the
rename to %APPDATA%/PerchVPN left those users signed out forever (the file
was never read again). Migration copies the legacy store byte-for-byte so
the existing validated refresh flow can renew it — no secrets are logged
or transformed anywhere.
"""

from __future__ import annotations

import logging

import pytest

from src.perchvpn_windows import platform
from src.perchvpn_windows.app import PerchVPNApp
from src.perchvpn_windows.config import WindowsConfig

LEGACY_TOKENS = '{"access_token":"legacy-access-abc","refresh_token":"legacy-refresh-def","scope":"x","obtained_at":1730300000,"expires_in":3600}'


@pytest.fixture()
def appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    legacy = tmp_path / "FoxyVPN"
    legacy.mkdir()
    (legacy / "tokens.json").write_text(LEGACY_TOKENS, encoding="utf-8")
    return tmp_path


class TestMigrationFunction:
    def test_copies_byte_for_byte_and_is_once(self, appdata):
        assert platform.get_token_path().exists() is False
        assert platform.migrate_legacy_tokens() is True
        target = platform.get_token_path()
        assert target.exists()
        assert target.read_text(encoding="utf-8") == LEGACY_TOKENS
        # A second run must not copy again (target now owns the file).
        assert platform.migrate_legacy_tokens() is False

    def test_never_overwrites_current_store(self, appdata):
        current = platform.get_token_path()
        current.parent.mkdir(parents=True, exist_ok=True)
        current.write_text('{"access_token":"current","refresh_token":"current"}')
        assert platform.migrate_legacy_tokens() is False
        assert "current" in current.read_text(encoding="utf-8")

    def test_absent_legacy_store_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPDATA", str(tmp_path))
        assert platform.migrate_legacy_tokens() is False
        assert platform.get_token_path().exists() is False

    def test_no_secrets_logged(self, appdata, caplog):
        with caplog.at_level(logging.DEBUG):
            platform.migrate_legacy_tokens()
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert "legacy-refresh-def" not in blob
        assert "legacy-access-abc" not in blob


class TestMigrationThroughAuthLoading:
    @pytest.mark.asyncio
    async def test_load_persisted_auth_sees_migrated_tokens(self, appdata, monkeypatch):
        app = PerchVPNApp(WindowsConfig(verify_exit=False))
        token_file = platform.get_token_path()
        monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

        auth = object()
        from unittest.mock import AsyncMock, patch
        with patch.object(app, "_obtain_auth", AsyncMock(return_value=auth)):
            assert await app.load_persisted_auth() is True
        assert app._runtime_auth is auth
        # The migrated file now lives under the current directory.
        assert "legacy-refresh-def" in token_file.read_text(encoding="utf-8")


class TestSignOutStaysSignedOut:
    def test_discard_deletes_legacy_store_and_writes_sentinel(self, appdata):
        assert platform.get_token_path().exists() is False
        platform.discard_legacy_tokens()
        assert not (appdata / "FoxyVPN" / "tokens.json").exists()
        assert platform.get_legacy_migration_marker_path().exists()
        # Migration must never run again from this point on.
        assert platform.migrate_legacy_tokens() is False
        assert platform.get_token_path().exists() is False

    @pytest.mark.asyncio
    async def test_sign_out_after_migration_survives_subsequent_handoff(
        self, appdata, monkeypatch
    ):
        from unittest.mock import AsyncMock, MagicMock, patch

        # Boot-like state migration copied the legacy store into the
        # current directory and marked it consumed; the app is signed in.
        assert platform.migrate_legacy_tokens() is True
        token_file = platform.get_token_path()
        monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

        app = PerchVPNApp(WindowsConfig(verify_exit=False))
        controller = MagicMock()
        controller.stop = AsyncMock()
        frontend = MagicMock()
        frontend.stop = AsyncMock()
        app._controller = controller
        app._frontend = frontend
        app._runtime_auth = MagicMock()

        await app.sign_out()

        # The explicit sign-out consumed the legacy store as well.
        assert app._runtime_auth is None
        assert not token_file.exists()
        assert not (appdata / "FoxyVPN" / "tokens.json").exists()
        assert platform.get_legacy_migration_marker_path().exists()

        # The very next handoff attempt must not resurrect credentials.
        with patch.object(
            app, "_obtain_auth", new_callable=AsyncMock
        ) as obtain:
            assert await app.load_persisted_auth() is False
            obtain.assert_not_called()
        assert app._runtime_auth is None
        assert platform.get_token_path().exists() is False
