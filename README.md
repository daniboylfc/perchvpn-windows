<div align="center">

# PerchVPN

**A Windows desktop client for the Firefox VPN / Mozilla VPN proxy service — full-tunnel TUN or a local SOCKS5/HTTP proxy, with live country switching.**

![Version](https://img.shields.io/badge/release-2.0.4-2f6f4f?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20x64-2f6f4f?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-2f6f4f?style=flat-square)

</div>

> **PerchVPN is an unofficial client.** It is not affiliated with, endorsed by, or supported by Mozilla. It authenticates with *your own* Firefox Account against the same service the official clients use, and it never ships, proxies, or shares credentials.

---

## Contents

- [Install](#install)
- [Networking modes at a glance](#networking-modes-at-a-glance)
- [TUN mode](#tun-mode)
- [Proxy mode](#proxy-mode)
- [Country hot-swap](#country-hot-swap)
- [DoH resolver pool](#doh-resolver-pool)
- [Operating mechanics](#operating-mechanics)
  - [1. Startup and readiness](#1-startup-and-readiness)
  - [2. Connect](#2-connect)
  - [3. Sustained transfer and upload flow control](#3-sustained-transfer-and-upload-flow-control)
  - [4. Disconnect and fail-closed recovery](#4-disconnect-and-fail-closed-recovery)
  - [5. System tray and cold-path hygiene](#5-system-tray-and-cold-path-hygiene)
- [Configuration reference](#configuration-reference)
- [Development](#development)

---

## Install

| Channel | Artifact | Notes |
|---|---|---|
| Installer | `PerchVPN-2.0.4-win64.msi` | Per-machine install, upgrade-aware. Requires elevation. |
| Portable | `PerchVPN-2.0.4-win64-portable.zip` | Extract anywhere writable and run `PerchVPN.exe`. No installer and no footprint under `Program Files`. |
| Verify | `SHA256SUMS.txt` | `Get-FileHash <file> -Algorithm SHA256` and compare. |

> **Prerequisite:** Microsoft Edge **WebView2 Evergreen Runtime** (already present on current Windows 10/11). The MSI refuses to install without it and points at the download; the portable build reports the same reason in a dialog instead of exiting silently.

**First run.** Sign in with your Firefox Account in the app window, pick a country, press **Connect**. Proxy mode is the default; enable **TUN** in settings to route the whole machine. The window's `X` hides PerchVPN to the tray and keeps the tunnel alive; quitting is explicit (**Quit** in the tray menu). Launching `PerchVPN.exe` again focuses the instance that is already running instead of starting a second one.

**Where data lives.** Nothing is written next to the executable.

| Path | Contents |
|---|---|
| `%APPDATA%\PerchVPN` | `config.json`, `status.json`, `proxy-state.json`, tokens, generated `sing-box.json`, TUN ownership record, app log |
| `%LOCALAPPDATA%\PerchVPN` | Startup/early-boot log, WebView2 profile |
| `%LOCALAPPDATA%\PerchVPN\webview2` | Persistent WebView2 user-data folder (keeps cold start fast) |

---

## Networking modes at a glance

| Mode | Scope | Transport to the edge | DNS | IPv6 | On failure |
|---|---|---|---|---|---|
| **TUN** | Whole system (all apps) | `sing-box` → local proxy → MASQUE (HTTP/1.1, HTTP/2 or HTTP/3/QUIC) | Tunnel DoH via the proxy (`remote-dns`), direct resolver for bypassed names | Full dual-stack, or forced `ipv4_only` / `ipv6_only` / preferred family | Fails closed: no partial tunnel, baseline restored or refused |
| **Proxy (SOCKS5)** | Proxy-aware apps | `H2ProxySession` / `H3ProxySession` / `H1ProxySession` → MASQUE | The app's own resolver | Follows the app and the dial | Connection refused / error surfaced, never a silent direct leak |
| **Proxy (HTTP)** | Proxy-aware apps | Same engine via the local HTTP proxy listener | The app's own resolver | Follows the app and the dial | As above |
| **Proxy-only mode** | Proxy-aware apps, TUN disabled | Same engine | App resolver | Follows the app and the dial | No TUN state to clean up |

> **One transport, two scopes.** Proxy mode is the default; TUN is opt-in. TUN mode does not reimplement the tunnel: `sing-box` forwards every captured flow into PerchVPN's own loopback SOCKS5 listener, which is the single MASQUE client. Fixing or tuning the transport therefore fixes both modes at once.

---

## TUN mode

TUN mode gives every application on the machine a system-wide tunnel, including apps that know nothing about proxies.

```
app traffic ──▶ Wintun adapter ──▶ sing-box (TUN inbound)
                                     │  auto_route, strict_route, stack=system
                                     ▼
                            perch-socks outbound
                                     │  127.0.0.1:1080 (SOCKS5)
                                     ▼
                      PerchVPN proxy engine ──▶ MASQUE ──▶ Fastly edge
```

**Adapter and routes.** `sing-box` creates a Wintun adapter and installs the default route; `172.19.0.1/30` (IPv4) and `fdfe:dcba:9876::/126` (IPv6) are the in-tunnel addresses. `auto_route` handles route installation and `strict_route` blocks traffic that would otherwise escape the tunnel, so the system cannot quietly fall back to the physical path.

**Split routing.** A curated exclusion list is emitted as `route_exclude_address`, keeping these on the physical adapter:

- private and link-local ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `127.0.0.0/8`, `fc00::/7`, `fe80::/10`) so LAN devices, printers and NAS stay reachable;
- host-local WSL `vEthernet` subnets, which `strict_route` would otherwise black-hole;
- the control-plane / edge `/32` bypass routes the elevated helper keeps on the physical gateway, so a mid-session country switch can dial the new edge without entering its own tunnel.

**Tunnel DNS.** `remote-dns` is DoH to a tunnel resolver, dialled through `perch-socks` — the query rides the VPN instead of leaking on the physical adapter. Presets: Cloudflare, Google, Quad9, AdGuard. A local resolver (`local-dns`, direct) serves bypassed names, and DNS hijack rules capture stray port-53 traffic.

**Port policy.** Fastly MASQUE edges only accept CONNECT to **80** and **443**; anything else is refused with HTTP 502 upstream. `sing-box` rejects other TCP ports locally instead of poisoning live `:443` streams, so an app asking for an unsupported port gets an immediate refusal rather than a stalled connection.

**Fail-closed ownership.** TUN bring-up and teardown are guarded by a persisted ownership record and a recovery engine:

- a *prepared* record is validated before any mutation, so a crash mid-setup cannot orphan routes or DNS;
- a live sidecar, an `Up` stale adapter, or an ambiguous probe **refuses** the operation rather than guessing;
- every baseline mutation is journaled and can be rolled back.

> **Why this matters:** a TUN client that half-connects is worse than one that does not connect. PerchVPN prefers a clean "not connected" to a system with a leaked default route.

---

## Proxy mode

Proxy mode exposes the same MASQUE engine to applications that speak proxies.

| Listener | Default | Purpose |
|---|---|---|
| SOCKS5 | `127.0.0.1:1080` | Primary entry point; used by `sing-box` in TUN mode and by any SOCKS-aware app. |
| HTTP proxy | `127.0.0.1:8080` (opt-in) | For apps that only speak HTTP `CONNECT`; loopback bind is enforced. |

**Sessions.** The engine negotiates the best transport the edge offers and keeps it alive across many flows:

- `H2ProxySession` — HTTP/2 CONNECT, multiplexed streams over one TLS connection;
- `H3ProxySession` — HTTP/3 (QUIC) with the same stream model;
- `H1ProxySession` — HTTP/1.1 CONNECT fallback.

Sessions are pooled, health-tracked and replaced on failure; a single bad upstream does not tear down the pool.

**Proxy-only mode.** With `proxy_only_mode` enabled, PerchVPN runs the proxy engine alone — no Wintun adapter, no route changes, no TUN ownership record. It is mutually exclusive with upstream-proxy chaining by design.

> **Leak posture:** a refused dial surfaces as an error to the client. The engine never silently falls back to a direct connection.

---

## Country hot-swap

Switching country mid-session replaces the upstream relay without re-running the whole bootstrap: the TUN adapter, routes, and local listener stay up while the exit changes.

**Sequence**

1. The UI acknowledges the new selection on the **first frame** (optimistic state) and shows the switch as in progress — the app never looks frozen while the backend works.
2. A monotonic `switch_id` is issued. Every later step checks it; work from a superseded switch is marked `stale` and discarded instead of overwriting the newer result.
3. The candidate relay is resolved and dialled on the physical path through the bypass routes, then swapped into the pool.
4. The old controller and pool are finalized in the background; the switch reports its phases (`plan`, `resolve`, `pin_upstream`, `dial`, `swap`, `verify_start`) with durations.

**Verification.** The new exit is confirmed by comparing the observed system egress against the expected exit **per address family**: an IPv6 exit from the SOCKS probe is compared with an IPv6 observation, never string-matched against an IPv4 observation. Country labels are treated as GeoIP opinions — an anycast edge can legitimately appear under several country databases — so a country match confirms the exit when an address comparison cannot.

**Rollback.** If the candidate never becomes active, the previous country's pins are kept and only the candidate's temporary pins are dropped. The live tunnel is never left in a half-switched state.

> **Result states:** `traffic_verified` (address or country confirmed) and `tunnel_operational` (traffic provably leaving through a non-baseline exit, exit identity inconclusive) both report **Connected**; only a baseline leak or an unverifiable state keeps the UI honest about it.

---

## DoH resolver pool

Hostnames that must resolve *before* the tunnel exists (control plane, relay endpoints, edge discovery) go through a racing DoH resolver.

| Provider | Endpoints | Dial |
|---|---|---|
| Cloudflare | `1.1.1.1`, `1.0.0.1` | HTTP/1.1 |
| Google | `8.8.8.8`, `8.8.4.4` | HTTP/1.1 |
| Quad9 | `9.9.9.9`, `149.112.112.112` | **HTTP/2** (ALPN) |

Quad9's DoH service rejects HTTP/1.1 with `505 HTTP Version Not Supported`, so its endpoints are dialled with HTTP/2 negotiated via ALPN while the others stay on HTTP/1.1.

**Racing and cancellation.** All endpoints for a provider are queried concurrently and the first success wins. Losers are always cancelled *and awaited* — a losing query that later raised used to produce "Task exception was never retrieved" whenever the caller timed out. Results are cached with a short TTL, and every query is bounded by a timeout.

---

## Operating mechanics

### 1. Startup and readiness

```
PerchVPN.exe
  ├─ durable logging + excepthook installed before any GUI import
  ├─ API thread: FastAPI + uvicorn  ── lifespan runs before serving
  ├─ readiness probe: GET /api/status, 50 ms → 250 ms backoff
  └─ pywebview window created ──▶ first paint ──▶ countries rendered
```

**Lifespan-accurate readiness.** The API is only considered ready once `uvicorn` has completed the FastAPI lifespan *and* `/api/status` returns a recognized status. The readiness timestamp is stamped **after** the answered request, so the log records the moment the service actually served, not the moment the probe started.

**Idle boot.** Startup prepares logging and token migration only. No auth dial, no proxy listener, no TUN helper, and no mode switch runs until you press Connect.

**Lazy imports.** The boot chain does not import `aioquic` or the HTTP/3 session module: `pool` and `controller` resolve `H3ProxySession` through a module `__getattr__`, so QUIC support is loaded only when an HTTP/3 dial needs it.

**Server-list cache reuse.** A server list the UI fetched seconds ago is authoritative for Connect (120-second freshness window), so pressing Connect does not repeat the same Remote Settings round trip. A background refresh still warms the snapshot at boot.

**Latency sweep pausing.** The per-country latency sweep pauses while a connect, disconnect or switch is in flight, so probe traffic never competes with the transition the user is waiting on.

### 2. Connect

1. **Optimistic UI.** The status flips to *connecting* immediately, before any network work, so the click always produces feedback.
2. **Fail-closed preconditions.** In TUN mode the pre-start gate validates the ownership record, the physical egress, and adapter state. Any ambiguity stops the attempt.
3. **Transport.** The proxy engine dials the selected relay; the pool negotiates HTTP/2 or HTTP/3 (HTTP/1.1 fallback) and the local SOCKS5 listener comes up.
4. **TUN bring-up.** The elevated helper starts the sidecar, creates the Wintun adapter, applies routes/DNS, and journals every mutation.
5. **Egress verification.** System traffic is probed per family and compared with the expected exit, with a baseline-leak check. Only then does the UI report **Connected**.

A per-phase summary (`preflight`, `auth`, `serverlist`, `controller`, `proxy`, `tun`) is written to the log for every connect.

### 3. Sustained transfer and upload flow control

Downloads and small requests are straightforward streams. Uploads are where HTTP/2 flow control actually bites, and it is handled explicitly:

```python
size = min(local_flow_control_window(stream_id), max_outbound_frame_size)
send_data(stream_id, payload[:size])
# window exhausted → clear, re-check, then wait for WINDOW_UPDATE
```

- payloads are split into admissible frames instead of being sent as one oversized frame;
- when the window runs dry the session waits for `WINDOW_UPDATE`, re-checking after clearing the event so a wakeup cannot be missed;
- a stalled write is bounded by a write timeout and raises `ProxyError`; a stream closed by the peer during upload raises immediately with the host and port;
- the write timeout is refreshed on progress, so it bounds a stall rather than the total duration of a large transfer.

> **Before this:** a 4 MiB upload raised `FlowControlError` and tore the stream down. Large uploads, video calls and media sends now complete.

### 4. Disconnect and fail-closed recovery

Disconnect is fast, but never at the cost of a truthful state.

1. **Teardown.** The sidecar is asked to stop; routes, DNS and adapter state are restored from the journaled baseline.
2. **Stale-adapter handling.** Windows keeps a removed Wintun device listed for a short while. The PnP ghost scan is polled at **100 ms** instead of sleeping a fixed second, so teardown finishes as soon as the device is really gone.
3. **Provably-owned rows.** A `Down` adapter row that is provably ours is released after a **0.75 s** grace once the baseline restore has finished — instead of waiting out the full 8-second absence window.
4. **Ownership handoff.** Teardown keeps a `released` ownership record so the next Connect can validate and consume it. This is what makes a clean reconnect possible without either latching fail-closed or blindly trusting a leftover row.
5. **Refusal, not guesswork.** A live sidecar, an `Up` stale adapter, or an ambiguous probe refuses the release. The app reports the failure and stays closed rather than claiming a clean state.

> **Fail-closed rule of thumb:** PerchVPN only declares success for state it can prove. Everything else is an error the UI shows.

### 5. System tray and cold-path hygiene

| Action | Behaviour |
|---|---|
| Window `X` | Hides to the notification area; the tunnel and API keep running. |
| Tray → **Open Perch VPN** | Restores the window. |
| Tray → Connect / Disconnect | Same action as the main button. |
| Tray → **Quit** | Explicit quit: ends the GUI loop so the API lifespan shutdown, TUN teardown and helper stop all run. |

**Cold-path hygiene.** At startup the process moves its working directory to `%LOCALAPPDATA%\PerchVPN`, so nothing is ever written beside the executable — a requirement for an MSI install under `Program Files` and the reason the portable build leaves its folder untouched. Release artifacts are additionally checked for forbidden files (logs, token files, `.env`) before packaging.

---

## Configuration reference

| Option | Default | Meaning |
|---|---|---|
| `listen_host` / `listen_port` | `127.0.0.1` / `1080` | SOCKS5 listener used by apps and by `sing-box`. |
| `http_proxy_enabled` / `http_proxy_port` | `false` / `8080` | Optional HTTP proxy listener (loopback only). |
| `proxy_only_mode` | `false` | Proxy engine only; ignores TUN even when enabled. |
| `tun_enabled` | `false` | Opt-in system-wide tunnel via Wintun + `sing-box`. |
| `ip_mode` | `dual_stack` | `dual_stack`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`. |
| `tunnel_dns_provider` | `default` | Cloudflare, Google, Quad9 or AdGuard DoH inside the tunnel. |
| `source_bind_ip` | auto | Pin control-plane egress to a physical address; auto-detected otherwise. |
| `upstream_proxy` | none | Chain through an upstream proxy (mutually exclusive with proxy-only mode). |

Settings are stored in `%APPDATA%\PerchVPN\config.json` and are editable from the app.

---

## Development

```powershell
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m pytest -q
```

```powershell
# Reproducible Windows bundle (same flags the release workflow enforces)
powershell -ExecutionPolicy Bypass -File scripts\build-candidate.ps1 -NoUpx
```

The suite covers the transport sessions, TUN lifecycle and recovery, DoH racing, hot-swap state machine, GUI/API contract and the packaging invariants. Windows-specific behaviour (Wintun, NDIS timing, WebView2) is unit-tested against fakes; live tunnel behaviour requires a real Windows host.

## License

MIT — see the `license` field in `pyproject.toml`.
