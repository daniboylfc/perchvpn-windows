# Atlas: System Architecture — PerchVPN Windows (`perchvpn-windows` v1.0.2)

Read this before running broad search/grep on the codebase. Update this file when the architecture changes.

## What this project is
Local SOCKS5 proxy client for the Mozilla VPN / Firefox VPN proxy service, Windows port.
Python >= 3.9. Key deps: `httpx[socks]`, `h2`, `cryptography`, `aioquic`, `fastapi`, `uvicorn`, `pywebview`.

## Package layout (src/ layout, setuptools)
| Package | Role |
|---|---|
| `src/perchvpn` | Core protocol/client library: auth (FXA), HTTP/2 + HTTP/3 (QUIC) transport, DoH resolver, server list, session tokens, guardian retry logic. |
| `src/perchvpn/proxy` | Proxy engine internals: `socks.py` (SOCKS5 server), `session.py`, `pool.py`, `relay.py`, `h3_session.py`, `upstream_proxy.py`. |
| `src/perchvpn_windows` | Windows application shell: CLI entry, GUI (pywebview), web UI (FastAPI/uvicorn), TUN lifecycle, diagnostics, sing-box config generation. |
| `src/foxyvpn`, `src/foxyvpn_windows` | Legacy compat shims — do not add new code here. |

## Entry points
- Console script: `perchvpn` → `perchvpn_windows.cli:main`
- Module run: `python -m perchvpn` → `perchvpn/__main__.py`
- App modes: GUI (pywebview), web (FastAPI + uvicorn on localhost), CLI. Mode switching covered by `tests/test_app_mode.py`, `tests/test_app_mode_switch.py`.

## Supporting dirs
- `tests/` — pytest suite (~1,002 tests; see `.opencode/memory/test-baseline.md`)
- `scripts/` — `build-candidate.ps1` (packaging), `verify-normal-wifi-tun.ps1`
- `graphify-out/` — prebuilt knowledge graph; query it before grepping (see AGENTS.md)
- `bin/`, `inspect/` — scratch/inspection, gitignored
