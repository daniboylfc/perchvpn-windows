"""Windows CLI entry point for Perch VPN."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import signal
import sys
from pathlib import Path
from typing import List, Optional

from perchvpn import auth as auth_module
from perchvpn import guardian, serverlist
from perchvpn.controller import ControllerConfig, ProxyController
from perchvpn.exitcheck import DEFAULT_EXIT_CHECK_TIMEOUT, DEFAULT_EXIT_CHECK_URL, verify_exit_country
from perchvpn.http_client import set_control_plane_proxy, set_control_plane_timeout
from perchvpn.logging_config import configure_logger
from perchvpn.proxy.session import DEFAULT_HANDSHAKE_TIMEOUT
from perchvpn.proxystate import ProxyStateStore, alternate_candidates, resolve_proxy

from .config import WindowsConfig, load_config, save_config, UpstreamProxyConfig
from .app import PerchVPNApp
from .platform import get_token_path
from .winconsole import ensure_interactive_console, restore_streams

logger = logging.getLogger("perchvpn_windows.cli")

GUARDIAN_ENDPOINT_DEFAULT = guardian.GUARDIAN_ENDPOINT_DEFAULT
DEFAULT_LISTEN = "127.0.0.1:1080"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="perchvpn",
        description="Local SOCKS5 proxy client for the Mozilla VPN / Firefox VPN proxy service (Windows)."
    )
    parser.add_argument("--tun-helper", default=None, metavar="SPEC", help=argparse.SUPPRESS)
    parser.add_argument("--tun-helper-recover", nargs="?", const="", default=None, metavar="JOURNAL", help=argparse.SUPPRESS)
    parser.add_argument("--api-proxy", default=None, help="Proxy URL (http/https/socks5/socks5h) used only for FxA/Guardian/Remote-Settings control-plane calls.")
    parser.add_argument("--guardian", default=GUARDIAN_ENDPOINT_DEFAULT, help="Guardian (Mozilla VPN control plane) endpoint.")
    parser.add_argument("--listen", default=DEFAULT_LISTEN, help="Local SOCKS5 listen address (host:port, or [ipv6]:port).")
    parser.add_argument("--login", action="store_true", help="Force a fresh interactive login, ignoring cached tokens.")
    parser.add_argument("--email", default=None, help="Firefox Accounts email (prompted if omitted and needed).")
    parser.add_argument("--password", default=None, help="Firefox Accounts password (prompted if omitted). Use with --login.")
    parser.add_argument("--session-token", default=None, help="An FxA session token, or a path to a file with one token per line for automatic rotation.")
    parser.add_argument("--print-info", action="store_true", help="Print account entitlement info and exit.")
    parser.add_argument("--list-servers", action="store_true", help="Print the available VPN server list and exit.")
    parser.add_argument("--proxy", default=None, help="Exact upstream proxy host:port (mutually exclusive with --country).")
    parser.add_argument("--country", default=None, help="Two-letter country code to select an upstream proxy from. Defaults to the recommended \"REC\" server when omitted.")
    parser.add_argument("--timeout", type=float, default=20.0, help="Default request timeout in seconds for FxA/Guardian/Remote-Settings control-plane calls.")
    parser.add_argument("--handshake-timeout", type=float, default=DEFAULT_HANDSHAKE_TIMEOUT, help="Upstream TLS/HTTP2/QUIC handshake timeout in seconds.")
    parser.add_argument("--http3", action="store_true", help="Use HTTP/3 (QUIC over UDP) instead of HTTP/2 (TCP) for the upstream tunnel transport.")
    parser.add_argument("--idle-timeout", type=float, default=0.0, help="Idle connection timeout in seconds (0 disables it).")
    parser.add_argument("--max-conns", type=int, default=256, help="Maximum concurrent client connections; 0 disables the limit.")
    parser.add_argument("--upstream-conns", type=int, default=1, help="Number of upstream sessions to pool (>1 enables client-IP affinity routing).")
    parser.add_argument("--status-file", default=None, help="Path to write a JSON status file describing proxy-pass health.")
    parser.add_argument("--proxy-state-file", default=None, help="Path to persist the selected upstream proxy across restarts.")
    parser.add_argument("--verify-exit", dest="verify_exit", action="store_true", default=True, help="Verify the exit country after connecting (default: enabled).")
    parser.add_argument("--no-verify-exit", dest="verify_exit", action="store_false", help="Disable exit-country verification.")
    parser.add_argument("--exit-check-url", default=DEFAULT_EXIT_CHECK_URL, help="URL used to verify the exit IP/country.")
    parser.add_argument("--exit-check-timeout", type=float, default=DEFAULT_EXIT_CHECK_TIMEOUT, help="Timeout in seconds for the exit-check request.")
    parser.add_argument("--verbose", action="store_true", help="Shorthand for --log-level debug.")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warn", "error"], help="Log level.")
    parser.add_argument("--log-format", default="text", choices=["text", "json"], help="Log output format.")
    parser.add_argument("--dashboard", dest="dashboard", action="store_true", default=True, help="Dashboard is enabled by default; accepted for launcher compatibility.")
    parser.add_argument("--no-dashboard", dest="dashboard", action="store_false", default=True, help="Disable the terminal dashboard.")
    parser.add_argument("--new-window", action="store_true", help="Launch dashboard in a dedicated Windows Terminal window.")
    parser.add_argument("--auth-only", action="store_true", help="Run authentication only and exit (for GUI handoff).")
    parser.add_argument("--version", action="store_true", help="Print version information and exit.")
    parser.add_argument("--proxy-only", action="store_true", help="Authenticate normally, run local SOCKS5 proxy with no VPN tunnel (CONNECT requests rejected).")
    parser.add_argument("--upstream-proxy", default=None, help="Upstream SOCKS5/HTTP proxy for H2 transport-level chaining (host:port).")
    parser.add_argument("--upstream-proxy-type", default="socks5", choices=["socks5", "http"], help="Upstream proxy type (default: socks5).")
    parser.add_argument("--upstream-proxy-username", default=None, help="Upstream proxy username (DPAPI-encrypted in config).")
    parser.add_argument("--upstream-proxy-password", default=None, help="Upstream proxy password (DPAPI-encrypted in config).")
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if args.proxy and args.country:
        raise SystemExit("--proxy and --country are mutually exclusive")
    if args.upstream_conns < 1:
        raise SystemExit("--upstream-conns must be >= 1")
    if args.max_conns < 0:
        raise SystemExit("--max-conns must be >= 0 (0 disables the limit)")
    if args.idle_timeout < 0:
        raise SystemExit("--idle-timeout must not be negative")
    if args.verify_exit and args.exit_check_timeout <= 0:
        raise SystemExit("--exit-check-timeout must be positive when exit verification is enabled")
    if args.password and not args.login:
        raise SystemExit("--password requires --login")
    if args.new_window and not args.dashboard:
        raise SystemExit("--new-window requires --dashboard (dashboard is enabled by default)")
    if args.auth_only and args.dashboard:
        # auth-only mode doesn't need dashboard; override to avoid conflicts
        args.dashboard = False
    if args.auth_only and args.new_window:
        raise SystemExit("--auth-only and --new-window are mutually exclusive")
    if args.proxy_only and args.http3:
        # Proxy-only mode disables the VPN tunnel; H3 is not applicable.
        raise SystemExit("--proxy-only and --http3 are mutually exclusive")


def _parse_listen(listen: str) -> tuple[Optional[str], int]:
    host: Optional[str]
    if listen.startswith("["):
        end = listen.find("]")
        if end == -1 or not listen[end + 1:].startswith(":"):
            raise SystemExit(f"invalid --listen value {listen!r}, expected host:port or [ipv6]:port")
        host = listen[1:end]
        port_str = listen[end + 2:]
    else:
        host, _, port_str = listen.rpartition(":")
        if not host:
            raise SystemExit(f"invalid --listen value {listen!r}, expected host:port or [ipv6]:port")
    try:
        port = int(port_str)
    except ValueError:
        raise SystemExit(f"invalid port in --listen {listen!r}")
    if port < 1 or port > 65535:
        raise SystemExit(f"port out of range in --listen {listen!r}")
    return host, port


async def _run_app(app, stop_event: Optional[asyncio.Event] = None) -> None:
    """Run the app and translate SIGINT into a graceful stop."""
    await app.initialize()
    if stop_event is None:
        stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    previous_handler = None

    def _on_sigint(signum, frame):
        loop.call_soon_threadsafe(stop_event.set)

    try:
        previous_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _on_sigint)
    except (ValueError, OSError):
        previous_handler = None

    run_task = asyncio.create_task(app.run())
    stop_task = asyncio.create_task(stop_event.wait())
    try:
        done, _ = await asyncio.wait(
            {run_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
        )
        if run_task in done:
            stop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stop_task
            run_task.result()
        else:
            run_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await run_task
    finally:
        if not stop_task.done():
            stop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await stop_task
        if previous_handler is not None:
            try:
                signal.signal(signal.SIGINT, previous_handler)
            except (ValueError, OSError):
                pass


async def _run_app_with_shutdown(
    app, stop_event: Optional[asyncio.Event] = None
) -> None:
    """Ensure shutdown runs on every exit path, including CLI interruption."""
    try:
        await _run_app(app, stop_event)
    finally:
        await app.shutdown()


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__
        print(f"perchvpn {__version__}")
        return 0

    if getattr(args, "tun_helper", None):
        from perchvpn_windows.tun_helper import helper_main
        return helper_main(args.tun_helper)

    if getattr(args, "tun_helper_recover", None) is not None:
        from perchvpn_windows import tun_helper as _tun_helper

        raw_journal = args.tun_helper_recover
        journal = Path(raw_journal) if raw_journal else None
        record = _tun_helper.load_journal(journal) if journal is not None else {}
        result = _tun_helper.recover_ownership(
            journal=record or {},
            terminate=lambda pid: _tun_helper.terminate_pid(
                pid, str(record.get("executable") or "")
            ),
            remove_adapter=_tun_helper._remove_adapter,
        )
        try:
            print(json.dumps(result))
        except Exception:
            pass
        return 0 if result.get("recovered") else 1

    _validate_args(args)
    configure_logger("debug" if args.verbose else args.log_level, args.log_format)

    if args.auth_only:
        return asyncio.run(_run_auth_only())

    upstream_proxy = None
    if args.upstream_proxy:
        host, _, port_str = args.upstream_proxy.rpartition(":")
        if not host or not port_str:
            raise SystemExit(f"invalid --upstream-proxy {args.upstream_proxy!r}, expected host:port")
        try:
            port = int(port_str)
        except ValueError:
            raise SystemExit(f"invalid port in --upstream-proxy {args.upstream_proxy!r}")
        if port < 1 or port > 65535:
            raise SystemExit(f"port out of range in --upstream-proxy {args.upstream_proxy!r}")
        upstream_proxy = UpstreamProxyConfig(
            host=host,
            port=port,
            type=args.upstream_proxy_type,
            username=args.upstream_proxy_username or "",
            password=args.upstream_proxy_password or "",
        )

    config = WindowsConfig(
        listen_host=_parse_listen(args.listen)[0] or "127.0.0.1",
        listen_port=_parse_listen(args.listen)[1],
        country=args.country,
        explicit_proxy=args.proxy,
        upstream_conns=args.upstream_conns,
        use_http3=args.http3,
        handshake_timeout=args.handshake_timeout,
        idle_timeout=args.idle_timeout,
        max_conns=args.max_conns,
        verify_exit=args.verify_exit,
        guardian_endpoint=args.guardian,
        log_level=args.log_level,
        log_format=args.log_format,
        dashboard=args.dashboard,
        new_window=args.new_window,
        upstream_proxy=upstream_proxy,
        proxy_only_mode=args.proxy_only,
    )

    app = PerchVPNApp(config)

    async def cli_obtain_auth(interactive: bool = True):
        return auth_module.obtain_auth(
            email=args.email,
            password=args.password,
            force_login=args.login,
            session_token_or_path=args.session_token,
            token_path=get_token_path(),
        )

    app._obtain_auth = cli_obtain_auth  # type: ignore

    async def run_app():
        await _run_app_with_shutdown(app)

    try:
        asyncio.run(run_app())
    except KeyboardInterrupt:
        # The graceful SIGINT path normally runs shutdown inside the loop.
        # This fallback covers interpreters where KeyboardInterrupt escapes
        # before the coroutine's finally block can run.
        try:
            asyncio.run(app.shutdown())
        except Exception:  # noqa: BLE001
            pass
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("fatal: %s", exc)
        return 1

    return 0


async def _run_auth_only() -> int:
    """Run authentication only and exit. Returns 0 on success, non-zero on failure.

    In windowed frozen builds (PerchVPN.exe --auth-only spawned by the GUI
    sign-in button) attaching a real console with AllocConsole + CONIN$ /
    CONOUT$ is mandatory: without it input()/getpass hit EOF instantly and
    the helper dies before the user can type anything. The console stays
    attached until authentication finishes instead of closing early.
    """
    original_streams = ensure_interactive_console()
    try:
        auth_module.obtain_auth(
            email=None,
            password=None,
            force_login=False,
            session_token_or_path=None,
            token_path=get_token_path(),
        )
        logger.info("Authentication completed successfully")
        return 0
    except KeyboardInterrupt:
        logger.info("Authentication cancelled by user")
        return 130
    except Exception as exc:  # noqa: BLE001
        logger.error("Authentication failed: %s", exc)
        return 1
    finally:
        # Always restore the captured std streams and free the console, on
        # success, cancellation and failure alike.
        restore_streams(original_streams)


if __name__ == "__main__":
    sys.exit(main())
