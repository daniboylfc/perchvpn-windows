"""Tests for OAuth token cache path override."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from perchvpn.tokens import (
    _token_path,
    load_tokens,
    save_tokens,
    delete_tokens,
    SavedTokens,
)
from perchvpn.auth import obtain_auth, _login_interactively, _refresh, _from_single_session_token


class TestTokenPathOverride:
    def test_default_token_path(self):
        """Default path should be ~/.perchvpn-tokens.json"""
        path = _token_path()
        assert path.name == ".perchvpn-tokens.json"
        assert str(path).startswith(str(Path.home()))

    def test_overridden_token_path(self, tmp_path):
        """Override should be respected."""
        custom = tmp_path / "custom-tokens.json"
        path = _token_path(custom)
        assert path == custom

    def test_load_tokens_with_override(self, tmp_path):
        """load_tokens should read from overridden path."""
        custom = tmp_path / "tokens.json"
        data = {
            "access_token": "test-access",
            "refresh_token": "test-refresh",
            "scope": "test",
            "obtained_at": 0,
            "expires_in": 3600,
        }
        import json
        custom.write_text(json.dumps(data))

        loaded = load_tokens(custom)
        assert loaded is not None
        assert loaded.access_token == "test-access"
        assert loaded.refresh_token == "test-refresh"

    def test_load_tokens_default_returns_none_when_missing(self):
        """load_tokens with no override should return None for missing default file."""
        # Use a non-existent path
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_path = Path(tmpdir) / "nonexistent-tokens.json"
            loaded = load_tokens(fake_path)
            assert loaded is None

    def test_save_tokens_with_override(self, tmp_path):
        """save_tokens should write to overridden path."""
        custom = tmp_path / "tokens.json"

        class MockToken:
            access_token = "new-access"
            refresh_token = "new-refresh"
            scope = "test-scope"
            expires_in = 7200

        saved = save_tokens(MockToken(), custom)
        assert custom.exists()
        assert saved.access_token == "new-access"

        # Verify file content
        import json
        data = json.loads(custom.read_text())
        assert data["access_token"] == "new-access"
        assert data["refresh_token"] == "new-refresh"

    def test_delete_tokens_with_override(self, tmp_path):
        """delete_tokens should delete overridden path."""
        custom = tmp_path / "tokens.json"
        custom.write_text("{}")

        delete_tokens(custom)
        assert not custom.exists()

    def test_delete_tokens_no_error_when_missing(self, tmp_path):
        """delete_tokens should not error when file missing."""
        custom = tmp_path / "missing.json"
        delete_tokens(custom)  # Should not raise


class TestAuthTokenPathIntegration:
    def test_obtain_auth_uses_token_path_for_cache(self, tmp_path, monkeypatch):
        """obtain_auth should use token_path for OAuth cache when provided."""
        custom = tmp_path / "tokens.json"

        # Create a mock session token file
        session_file = tmp_path / "session-tokens.txt"
        session_file.write_text("valid-session-token-hex\n")

        # Mock fxa.oauth_token to avoid network calls
        import perchvpn.auth as auth_module

        def mock_oauth_token(session_token):
            from perchvpn.fxa import TokenResponse
            return TokenResponse(
                access_token="test-access",
                refresh_token="test-refresh",
                expires_in=3600,
                scope="test",
            )

        monkeypatch.setattr(auth_module.fxa, "oauth_token", mock_oauth_token)

        result = obtain_auth(
            session_token_or_path=str(session_file),
            token_path=custom,
        )

        assert result.access_token == "test-access"
        assert custom.exists()

    def test_rotate_session_token_uses_token_path(self, tmp_path, monkeypatch):
        """rotate_session_token should use token_path for OAuth cache."""
        custom = tmp_path / "tokens.json"

        # Create a session token pool
        pool_file = tmp_path / "session-pool.txt"
        pool_file.write_text("token1\ntoken2\n")

        import perchvpn.auth as auth_module

        def mock_oauth_token(session_token):
            from perchvpn.fxa import TokenResponse
            return TokenResponse(
                access_token="rotated-access",
                refresh_token="rotated-refresh",
                expires_in=3600,
                scope="test",
            )

        monkeypatch.setattr(auth_module.fxa, "oauth_token", mock_oauth_token)

        # First obtain_auth to create RuntimeAuth with pool
        auth = obtain_auth(
            session_token_or_path=str(pool_file),
            token_path=custom,
        )

        # Rotate
        rotated = auth_module.rotate_session_token(auth, token_path=custom)

        assert rotated is not None
        assert rotated.access_token == "rotated-access"
        assert custom.exists()

    def test_refresh_uses_token_path(self, tmp_path, monkeypatch):
        """_refresh should save to token_path."""
        custom = tmp_path / "tokens.json"

        # Create initial tokens
        initial_data = {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "scope": "test",
            "obtained_at": 0,
            "expires_in": 3600,
        }
        import json
        custom.write_text(json.dumps(initial_data))

        from perchvpn.tokens import SavedTokens
        saved = load_tokens(custom)
        assert saved is not None

        import perchvpn.auth as auth_module

        def mock_refresh_token(refresh_token):
            from perchvpn.fxa import TokenResponse
            return TokenResponse(
                access_token="refreshed-access",
                refresh_token="refreshed-refresh",
                expires_in=3600,
                scope="test",
            )

        monkeypatch.setattr(auth_module.fxa, "refresh_token", mock_refresh_token)

        result = auth_module._refresh(saved, custom)

        assert result.access_token == "refreshed-access"

        # Verify file was updated
        reloaded = load_tokens(custom)
        assert reloaded.access_token == "refreshed-access"