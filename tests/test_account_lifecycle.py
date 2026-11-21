import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.perchvpn_windows.app import PerchVPNApp
from src.perchvpn_windows.config import WindowsConfig
from src.perchvpn_windows import api as api_module
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_load_persisted_auth_success(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc","refresh_token":"def","scope":"x","obtained_at":1,"expires_in":3600}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    auth = MagicMock()
    with patch.object(app, "_obtain_auth", AsyncMock(return_value=auth)):
        assert await app.load_persisted_auth() is True
    assert app._runtime_auth is auth


@pytest.mark.asyncio
async def test_load_persisted_auth_rejects_invalid(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    token_file = tmp_path / "tokens.json"
    token_file.write_text("{not json")
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    with patch.object(app, "_obtain_auth", AsyncMock(side_effect=RuntimeError("bad"))):
        assert await app.load_persisted_auth() is False
    assert app._runtime_auth is None


@pytest.mark.asyncio
async def test_sign_out_stops_controller_and_clears_state(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    controller = MagicMock()
    controller.stop = AsyncMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc"}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    await app.sign_out()

    controller.stop.assert_awaited_once()
    frontend.stop.assert_awaited_once()
    assert app._runtime_auth is None
    assert not token_file.exists()


@pytest.mark.asyncio
async def test_account_logout_failure_does_not_report_success():
    app = MagicMock()
    app.sign_out = AsyncMock(side_effect=RuntimeError("boom"))
    api_module._app = app
    try:
        await api_module.account_logout()
    except HTTPException as exc:
        assert exc.status_code == 500
    else:
        raise AssertionError("expected HTTPException")


@pytest.mark.asyncio
async def test_account_logout_success():
    app = MagicMock()
    app.sign_out = AsyncMock(return_value=None)
    api_module._app = app
    result = await api_module.account_logout()
    assert result.status == "signed_out"
    app.sign_out.assert_awaited_once()


@pytest.mark.asyncio
async def test_sign_out_partial_shutdown_invalidates_state(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    controller = MagicMock()
    controller.stop = AsyncMock(side_effect=RuntimeError("controller boom"))
    controller.auth = MagicMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc"}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    with pytest.raises(RuntimeError, match="controller boom"):
        await app.sign_out()

    controller.stop.assert_awaited_once()
    frontend.stop.assert_awaited_once()
    assert controller.auth is None
    assert app._controller is None
    assert app._runtime_auth is None
    assert not token_file.exists()


@pytest.mark.asyncio
async def test_sign_out_repeated_is_safe(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    controller = MagicMock()
    controller.stop = AsyncMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc"}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    await app.sign_out()
    await app.sign_out()

    assert app._runtime_auth is None
    assert not token_file.exists()


@pytest.mark.asyncio
async def test_load_persisted_auth_serializes_concurrent_handoff(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc","refresh_token":"def","scope":"x","obtained_at":1,"expires_in":3600}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    started = asyncio.Event()
    release = asyncio.Event()

    call_count = {"n": 0}

    async def fake_obtain(interactive=False):
        call_count["n"] += 1
        started.set()
        await release.wait()
        return MagicMock()

    with patch.object(app, "_obtain_auth", side_effect=fake_obtain):
        tasks = [asyncio.create_task(app.load_persisted_auth()) for _ in range(5)]
        await started.wait()
        release.set()
        results = await asyncio.gather(*tasks)

    assert results == [True, True, True, True, True]
    assert call_count["n"] == 1
    assert app._runtime_auth is not None


@pytest.mark.asyncio
async def test_load_persisted_auth_failed_credentials_not_installed(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc","refresh_token":"def","scope":"x","obtained_at":1,"expires_in":3600}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    with patch.object(app, "_obtain_auth", AsyncMock(side_effect=RuntimeError("bad"))):
        results = await asyncio.gather(
            *[app.load_persisted_auth() for _ in range(3)]
        )

    assert results == [False, False, False]
    assert app._runtime_auth is None


@pytest.mark.asyncio
async def test_load_persisted_auth_failed_then_retry_succeeds(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc","refresh_token":"def","scope":"x","obtained_at":1,"expires_in":3600}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    auth = MagicMock()
    with patch.object(app, "_obtain_auth", AsyncMock(side_effect=[RuntimeError("bad"), auth])):
        assert await app.load_persisted_auth() is False
        assert await app.load_persisted_auth() is True
    assert app._runtime_auth is auth


@pytest.mark.asyncio
async def test_load_persisted_auth_disabled_during_logout(tmp_path, monkeypatch):
    app = PerchVPNApp(WindowsConfig(explicit_proxy="1.2.3.4:1080", verify_exit=False))
    app._auth_handoff_disabled = True
    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"abc","refresh_token":"def","scope":"x","obtained_at":1,"expires_in":3600}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    with patch.object(app, "_obtain_auth", AsyncMock(return_value=MagicMock())):
        assert await app.load_persisted_auth() is False
    assert app._runtime_auth is None

@pytest.mark.asyncio
async def test_sign_out_invalidates_session_token_path(tmp_path, monkeypatch):
    alt_token = tmp_path / "session_token.json"
    unrelated = tmp_path / "unrelated.txt"
    alt_token.write_text('{"access_token":"alt"}')
    unrelated.write_text("keep")

    app = PerchVPNApp(
        WindowsConfig(
            explicit_proxy="1.2.3.4:1080",
            verify_exit=False,
            session_token_path=str(alt_token),
        )
    )
    controller = MagicMock()
    controller.stop = AsyncMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"primary"}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    await app.sign_out()

    assert not token_file.exists()
    assert not alt_token.exists()
    assert unrelated.exists()
    assert app._runtime_auth is None


@pytest.mark.asyncio
async def test_sign_out_failure_keeps_handoff_disabled_and_clears_auth(tmp_path, monkeypatch):
    alt_token = tmp_path / "session_token.json"
    alt_token.write_text('{"access_token":"alt"}')

    app = PerchVPNApp(
        WindowsConfig(
            explicit_proxy="1.2.3.4:1080",
            verify_exit=False,
            session_token_path=str(alt_token),
        )
    )
    controller = MagicMock()
    controller.stop = AsyncMock(side_effect=RuntimeError("controller boom"))
    controller.auth = MagicMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    # Make primary token deletion fail while leaving the token in place.
    token_dir = tmp_path / "token_dir"
    token_dir.mkdir()
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_dir)

    with pytest.raises(RuntimeError, match="controller boom"):
        await app.sign_out()

    assert app._auth_handoff_disabled is True
    assert app._runtime_auth is None
    # Surviving credentials cannot be reloaded while handoff is disabled.
    with patch.object(app, "_obtain_auth", AsyncMock(return_value=MagicMock())):
        assert await app.load_persisted_auth() is False
    assert app._runtime_auth is None


@pytest.mark.asyncio
async def test_sign_out_alternate_token_deletion_failure_fail_closed(tmp_path, monkeypatch):
    alt_token = tmp_path / "session_token_dir"
    alt_token.mkdir()  # unlink() fails, leaving alternate credential in place

    app = PerchVPNApp(
        WindowsConfig(
            explicit_proxy="1.2.3.4:1080",
            verify_exit=False,
            session_token_path=str(alt_token),
        )
    )
    controller = MagicMock()
    controller.stop = AsyncMock()
    frontend = MagicMock()
    frontend.stop = AsyncMock()
    app._controller = controller
    app._frontend = frontend
    app._runtime_auth = MagicMock()

    token_file = tmp_path / "tokens.json"
    token_file.write_text('{"access_token":"primary"}')
    monkeypatch.setattr("src.perchvpn_windows.app.get_token_path", lambda: token_file)

    with pytest.raises(Exception):
        await app.sign_out()

    assert app._auth_handoff_disabled is True
    assert app._runtime_auth is None
    with patch.object(app, "_obtain_auth", AsyncMock(return_value=MagicMock())):
        assert await app.load_persisted_auth() is False
    assert app._runtime_auth is None
