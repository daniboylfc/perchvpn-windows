<div align="center">

# PerchVPN

**Windows client for the Firefox VPN / Mozilla VPN service** — local SOCKS5/HTTP proxy by default, whole-system Wintun tunnel as an opt-in, live country switching in both.

![Release](https://img.shields.io/badge/release-2.0.4-2f6f4f?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20x64-2f6f4f?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-2f6f4f?style=flat-square)

</div>

> **Unofficial client.** Not affiliated with, endorsed by, or supported by Mozilla. PerchVPN authenticates with *your own* Firefox Account against the same service the official clients use. It ships no credentials and never proxies them.

---

## Contents

- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Networking modes](#networking-modes)
  - [Proxy mode (default)](#proxy-mode-default)
  - [System-wide TUN mode (opt-in)](#system-wide-tun-mode-opt-in)
  - [Country hot-swap](#country-hot-swap)
  - [DoH resolver pool](#doh-resolver-pool)
- [Operating lifecycle](#operating-lifecycle)
  - [1. Startup and readiness](#1-startup-and-readiness)
  - [2. Connect](#2-connect)
  - [3. Sustained transfer and upload flow control](#3-sustained-transfer-and-upload-flow-control)
  - [4. Disconnect and ownership handoff](#4-disconnect-and-ownership-handoff)
  - [5. Tray, single instance, cold path](#5-tray-single-instance-cold-path)
- [Configuration reference](#configuration-reference)
- [Development and tests](#development-and-tests)
- [License](#license)

---

## Architecture

```
WebView2 UI (web/index.html)
   │  HTTP + WebSocket on 127.0.0.1:8765
   ▼
FastAPI (uvicorn, lifespan-gated)  ·  status · config · lifecycle
   │
   ├─ proxy mode (default) ──▶ SOCKS5 127.0.0.1:1080 (+ HTTP 8080 opt-in)
   └─ TUN mode (opt-in) ────▶ helper → Wintun "PerchVPN" → sing-box
                                 └─ outbound "perch-socks" → 127.0.0.1:1080
   ▼
ProxyController → SessionPool (H2 · H3 · H1) → MASQUE edge (Fastly) → exit
```

Three invariants hold end to end:

- **One transport, two scopes.** TUN mode does not reimplement the tunnel: `sing-box` hands every captured flow to the same loopback SOCKS5 listener that proxy-aware apps use. A transport fix applies to both modes.
- **Fail closed.** The client claims a state only when it can prove it. A half-built tunnel is torn down or refused, never reported as connected.
- **No writes beside the executable.** All state lives under `%APPDATA%\PerchVPN` and `%LOCALAPPDATA%\PerchVPN`, which makes an MSI install under `Program Files` and a portable extract equally safe.

---

## Quickstart

| Channel | Artifact | Notes |
|---|---|---|
| Installer | `PerchVPN-2.0.4-win64.msi` | Per-machine, upgrade-aware, requires elevation. |
| Portable | `PerchVPN-2.0.4-win64-portable.zip` | Extract anywhere writable and run `PerchVPN.exe`. No installer, no `Program Files` footprint. |
| Verify | `SHA256SUMS.txt` | `Get-FileHash <file> -Algorithm SHA256` and compare. |

> **Prerequisite:** Microsoft Edge **WebView2 Evergreen Runtime** (already present on current Windows 10/11). The MSI refuses to install without it and links the download; the portable build reports the same reason in a dialog instead of exiting silently.

**First run.** Sign in with your Firefox Account, pick a country, press **Connect**. Proxy mode is the default. Enable **TUN** in settings to route the whole machine.

**Window and tray.** `X` hides to the notification area and keeps the tunnel running; quitting is explicit via the tray menu. Launching `PerchVPN.exe` while it runs focuses the existing instance instead of starting a second one.

**Where data lives.** Nothing is written next to the executable.

| Path | Contents |
|---|---|
| `%APPDATA%\PerchVPN` | `config.json`, `status.json`, `proxy-state.json`, `tokens.json`, `sing-box.json`, `tun-ownership.json`, `perchvpn.log` |
| `%LOCALAPPDATA%\PerchVPN` | Early-boot `perchvpn.log`, crash / faulthandler logs |
| `%LOCALAPPDATA%\PerchVPN\webview2` | Persistent WebView2 profile (keeps cold start fast) |

---

## Networking modes

| Mode | Default | Scope | Transport to the edge | DNS | IPv6 | On failure |
|---|---|---|---|---|---|---|
| **Proxy — SOCKS5** | **yes** | Proxy-aware apps | Configured transport: H2 (default), H3, or H1 | The app's resolver | Follows the app | Dial error returned; no silent direct fallback |
| **Proxy — HTTP** | opt-in | Proxy-aware apps | Same engine, local HTTP `CONNECT` listener | The app's resolver | Follows the app | As above |
| **Proxy-only** | opt-in | Proxy-aware apps, TUN suppressed | Same engine | The app's resolver | Follows the app | No TUN state to clean up |
| **System-wide TUN** | opt-in | Every app on the machine | `sing-box` → loopback SOCKS5 → same engine | Tunnel DoH via the proxy (`remote-dns`) + `local-dns` for bypassed names | `dual_stack` or a forced/preferred family | Fails closed; baseline restored or the operation is refused |

---

### Proxy mode (default)

The engine is a MASQUE client for Fastly's relay edges. Each session type maps to one upstream protocol:

| Session | Protocol | Role |
|---|---|---|
| `H2ProxySession` | HTTP/2 `CONNECT` | Default. Multiplexed streams over one TLS connection. |
| `H3ProxySession` | HTTP/3 (QUIC) | Selected with `transport_version="h3"`; `use_http3` is the legacy alias. |
| `H1ProxySession` | HTTP/1.1 `CONNECT` | Explicit `transport_version="h1"` parity mode. |

Transport is chosen by configuration (`transport_version`), not negotiated. HTTP/3 downgrades to HTTP/2 automatically on a QUIC timeout or a close storm (4 session closes in 10 s) unless the transport is pinned.

**Pool behaviour.** `SessionPool` grows on demand up to a stream-capacity ceiling, spaces replacement dials by at least 0.25 s so a burst of short-lived flows cannot storm the edge with parallel TLS handshakes, and replaces sessions marked unhealthy — a stalled upload or a stream the peer closed marks the session so the drain happens on the next acquire.

**Listeners.**

| Listener | Default | Purpose |
|---|---|---|
| SOCKS5 | `127.0.0.1:1080` | Primary entry point; also consumed by `sing-box`. |
| HTTP proxy | `127.0.0.1:8080`, opt-in | For apps that only speak HTTP `CONNECT`. Loopback bind is enforced. |

**Proxy-only mode.** `proxy_only_mode` runs the engine alone — no Wintun adapter, no routes, no ownership record. It is mutually exclusive with upstream-proxy chaining by design.

> **Leak posture:** a refused dial is an error to the client. The engine never falls back to a direct connection.

---

### System-wide TUN mode (opt-in)

Every application gets the tunnel, including apps that know nothing about proxies.

```
app traffic ──▶ Wintun "PerchVPN" ──▶ sing-box (TUN inbound)
                                        │ auto_route · strict_route · stack=system
                                        ▼
                               outbound "perch-socks"
                                        │ 127.0.0.1:1080 (SOCKS5)
                                        ▼
                    PerchVPN proxy engine ──▶ MASQUE ──▶ Fastly edge
```

**Adapter and routes.** `sing-box` owns the Wintun adapter and the default route. In-tunnel addresses are `172.19.0.1/30` (IPv4) and `fdfe:dcba:9876::1/126` (IPv6). `auto_route` installs routes; `strict_route` blocks traffic that would otherwise escape, so the system cannot silently fall back to the physical path.

**Split routing.** `route_exclude_address` keeps these off the tunnel:

- RFC1918, link-local and loopback ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `127.0.0.0/8`, `fc00::/7`, `fe80::/10`), so LAN devices, printers and NAS stay reachable;
- host-local WSL `vEthernet` subnets, which `strict_route` would otherwise black-hole (detected live via the native IP Helper);
- the control-plane and edge `/32` bypass routes the elevated helper keeps on the physical gateway, so a mid-session switch can reach the new edge without entering its own tunnel.

**Tunnel DNS.** `remote-dns` is DoH to a tunnel resolver, dialled through `perch-socks`, so queries ride the VPN instead of leaking on the physical adapter. Presets: Cloudflare (default), Google, Quad9, AdGuard. `local-dns` (direct) serves bypassed names; hijack rules capture stray protocol-DNS and port-53 traffic.

**Port policy.** MASQUE edges accept `CONNECT` only to **80** and **443**; other ports come back as HTTP 502 and can poison live `:443` streams. `sing-box` therefore rejects every other TCP port locally, giving the app an immediate refusal instead of a stalled connection. UDP is rejected, and port 853 is blocked.

**Fail-closed ownership.** A persisted record plus a recovery engine guard bring-up and teardown:

- a `prepared` record is validated before any mutation, so a crash mid-setup cannot orphan routes or DNS;
- a live sidecar, an `Up` stale adapter, or an inconclusive probe **refuses** the operation rather than guessing;
- every baseline mutation is journaled, and restoration completes before the record is cleared.

> A TUN client that half-connects is worse than one that does not connect. PerchVPN prefers an honest "not connected" to a leaked default route.

---

### Country hot-swap

A switch replaces the upstream relay without re-bootstrapping: the Wintun adapter, routes and listener stay up.

1. **Frame 1 is optimistic.** The country row repaints on the click, before any network call; a rejected request rolls the row back, so the UI never claims a country the backend refused.
2. **Monotonic `switch_id`.** Each step re-checks it; work from a superseded switch is marked `stale` and discarded instead of overwriting the newer result.
3. **Candidate on the physical path.** The new relay is resolved and dialled through the bypass routes, then swapped into the pool.
4. **Background handoff.** The old controller and pool are finalized asynchronously. Phases are timed (`plan`, `resolve`, `pin_upstream`, `dial`, `swap`, `verify_start`).

**Verification is per address family.** An IPv6 exit from the SOCKS probe is compared with an IPv6 observation, never string-matched against an IPv4 address. Country labels are treated as GeoIP opinions — an anycast edge can legitimately appear under several databases — so a country match confirms the exit when address comparison cannot. Both sides of the comparison read Cloudflare's `/cdn-cgi/trace`; proxy responses are capped at 64 KiB. `REC` selects the service's rotating recommended server.

**Prewarm.** Hovering or keyboard-focusing a country fires `POST /api/prewarm`, which resolves that relay's host into the DoH cache so the switch itself is a dial, not a lookup. `system` as `resolver_dns_provider` disables prewarm.

**Rollback.** If the candidate never becomes active, the previous country's pins are kept and only the candidate's temporary pins are dropped.

| State | Meaning | UI |
|---|---|---|
| `traffic_verified` | Exit identity confirmed | Connected |
| `tunnel_operational` | Adapter and routes up; traffic leaves via a non-baseline exit; identity inconclusive | Connected |
| `degraded` | System traffic still exits through the physical path — routes are not effective | Degraded |

---

### DoH resolver pool

Hostnames that must resolve before the tunnel exists (control plane, relay endpoints, edge discovery) go through a racing DoH resolver.

| Provider | Endpoints | Dial |
|---|---|---|
| Cloudflare | `1.1.1.1`, `1.0.0.1` | HTTP/1.1 |
| Google | `8.8.8.8`, `8.8.4.4` | HTTP/1.1 |
| Quad9 | `9.9.9.9`, `149.112.112.112` | **HTTP/2** (ALPN) |

Quad9 rejects HTTP/1.1 with `505 HTTP Version Not Supported`, so those two endpoints are dialled over HTTP/2 via ALPN; the others stay on HTTP/1.1.

`automatic` (the default `bootstrap_dns_provider` and `resolver_dns_provider`) races **all six endpoints across all three providers**; a named provider races its own two. The first success wins; losers are cancelled *and awaited*, so a losing query that later raises cannot surface as "Task exception was never retrieved". Results are cached with a TTL and every query is timeout-bounded. `system` delegates to the OS resolver.

---

## Operating lifecycle

### 1. Startup and readiness

```
PerchVPN.exe
  ├─ durable logging + excepthook installed before any GUI import
  ├─ working directory moved to %LOCALAPPDATA%\PerchVPN
  ├─ API thread: FastAPI + uvicorn — lifespan completes before serving
  ├─ readiness probe: GET /api/status, 50 ms → 250 ms backoff
  └─ pywebview window ──▶ first paint ──▶ countries rendered
```

**Idle boot.** The lifespan calls `initialize_idle()`: logging, token migration and an optional source-bind only. No auth dial, proxy listener, TUN helper or mode switch runs until Connect.

**Lifespan-accurate readiness.** Ready means the uvicorn lifespan completed *and* `/api/status` answered with a recognized payload. The readiness mark is stamped **after** the answered request, so the log records when the service actually served, not when the probe started.

**Lazy imports.** The boot chain never imports `aioquic` or the HTTP/3 session module: `pool` and `controller` resolve `H3ProxySession` through module-level `__getattr__`, so QUIC code loads only when an HTTP/3 dial needs it.

**Server-list cache reuse.** A list the UI fetched within 120 s is authoritative for Connect, so pressing Connect does not repeat the Remote Settings round trip. A non-blocking refresh still warms the snapshot at boot.

**Latency sweep pausing.** The per-country latency sweep pauses while a connect, disconnect or switch is in flight, so probe traffic never competes with the transition the user is waiting on.

### 2. Connect

1. **Optimistic paint, deferred dial.** The UI paints *Connecting* and returns, then issues `POST /api/restart` on the next task — the click always produces feedback before any blocking work.
2. **Fail-closed preconditions.** In TUN mode the pre-start gate validates the ownership record, the physical path and adapter state. Ambiguity stops the attempt.
3. **Transport.** The controller dials the selected candidate (configured transport) and brings up the loopback SOCKS5 listener.
4. **TUN bring-up.** The elevated helper starts the sidecar, creates the Wintun adapter and applies routes/DNS, journaling each mutation.
5. **Exit verification.** System egress is probed per family, compared with the expected exit, and checked against the pre-connect baseline for leaks. Only then does the UI report **Connected**.

Each connect writes a per-phase summary to the log: `preflight`, `auth`, `serverlist`, `controller`, `proxy`, `tun`.

### 3. Sustained transfer and upload flow control

Downloads and small requests stream directly. Uploads are where HTTP/2 flow control bites, and it is handled explicitly:

```python
window = conn.local_flow_control_window(stream_id)
size   = min(window, conn.max_outbound_frame_size)   # admissible frame
conn.send_data(stream_id, view[:size]); view = view[size:]
# window dry → clear, re-check, then wait for WINDOW_UPDATE
```

- payloads are split into admissible frames instead of being sent as one oversized frame;
- the event is cleared **before** re-checking, so a `WINDOW_UPDATE` arriving between check and wait cannot be missed;
- a stalled write is bounded by `WRITE_TIMEOUT` (30 s) and marks the session unhealthy; a stream closed by the peer raises `ProxyError` naming host, port and stream;
- the deadline is refreshed on progress, so it bounds a stall rather than the total transfer time.

> A 4 MiB upload used to raise `FlowControlError` and tear the stream down. Large uploads, video calls and media sends now complete.

### 4. Disconnect and ownership handoff

Disconnect is fast, but never at the cost of a truthful state.

1. **Teardown.** The sidecar is asked to stop; routes, DNS and adapter state are restored from the journaled baseline.
2. **Ghost-adapter polling.** Windows keeps a removed Wintun device listed for a while. The PnP scan polls every **100 ms** instead of sleeping a fixed second, so teardown finishes when the device is really gone.
3. **Provably-owned rows.** A `Down` row that is provably ours is released **0.75 s** after a finished baseline restore, instead of waiting out the **8 s** verification window.
4. **Ownership handoff.** Teardown persists a `released` record. The next Connect validates and consumes it — a clean reconnect without either latching fail-closed or blindly trusting a leftover row.
5. **Refusal, not guesswork.** A live sidecar, an `Up` stale adapter, or an inconclusive probe refuses the release. The app reports the failure and stays closed.

> **Rule of thumb:** only provable state is success. Everything else is an error the UI shows.

### 5. Tray, single instance, cold path

| Action | Behaviour |
|---|---|
| Window `X` | Hides to the notification area; tunnel and API keep running. |
| Tray → **Open Perch VPN** | Restores the window. |
| Tray → **Connect** / **Disconnect** | Same action as the main button. |
| Tray → **Quit** | Ends the GUI loop, so the API lifespan shutdown, TUN teardown and helper stop all run. |
| Second launch | Focuses the running instance; no second process. |

**Cold-path hygiene.** Startup moves the working directory to `%LOCALAPPDATA%\PerchVPN`, so nothing is ever written beside the executable. Release packaging additionally rejects any bundle containing `auth.json`, `tokens.json`, `settings.json`, `.env` or `*.log`.

---

## Configuration reference

| Option | Default | Meaning |
|---|---|---|
| `listen_host` / `listen_port` | `127.0.0.1` / `1080` | SOCKS5 listener used by apps and by `sing-box`. |
| `http_proxy_enabled` / `http_proxy_port` | `false` / `8080` | Optional HTTP proxy listener; loopback only. |
| `tun_enabled` | `false` | Opt-in system-wide tunnel (Wintun + `sing-box`). |
| `proxy_only_mode` | `false` | Proxy engine only; TUN is ignored even when enabled. |
| `transport_version` | `h2` | `h1`, `h2` or `h3` upstream transport. |
| `use_http3` | `false` | Legacy HTTP/3 override; ignored while `transport_version` is `h2` or `h3`. |
| `ip_mode` | `dual_stack` | `dual_stack`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `tunnel_dns_provider` | `default` | Tunnel DoH: Cloudflare, Google, Quad9, AdGuard or `custom`. |
| `bootstrap_dns_provider` | `automatic` | DoH pool used before the tunnel exists. |
| `resolver_dns_provider` | `automatic` | DoH provider for relay-host pre-resolution; `system` uses the OS resolver. |
| `source_bind_ip` | auto | Pin control-plane egress to a physical address. |
| `upstream_proxy_enabled` / `upstream_proxy` | `false` / none | Chain through an upstream proxy (mutually exclusive with proxy-only mode). |

Settings live in `%APPDATA%\PerchVPN\config.json` and are editable from the app.

---

## Development and tests

```powershell
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest -q
```

```powershell
# Reproducible Windows bundle with the flags the release workflow enforces
powershell -ExecutionPolicy Bypass -File scripts\build-candidate.ps1 -NoUpx
```

The suite covers transport sessions and flow control, the TUN lifecycle and recovery engine, DoH racing, the hot-swap state machine, the GUI/API contract and packaging invariants. Windows-only behaviour (Wintun, NDIS timing, WebView2) is unit-tested against fakes; live tunnel behaviour requires a real Windows host.

## License

MIT — see the `license` field in `pyproject.toml`.
