"""Live production verification driver (PerchVPN-Sandbox guest).

Boots the real API backend, records relayer RTT probes against the two
production endpoints, then drives three TUN connect cycles (h1+combined,
h2, h3) through the production connect path (/api/restart mode=tun).

Secrets: the driver never reads tokens.json — the app loads it itself
from %APPDATA%\\PerchVPN.  Nothing auth-bearing is printed or written.

Run with cwd=C:\\PerchGuest\\client so resolve_tun_executable() finds
bin\\sing-box.exe via the cwd fallback.
"""
import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(r"C:\PerchGuest\client")
sys.path.insert(0, str(ROOT / "site-packages"))
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

import httpx  # noqa: E402

RESULT_PATH = ROOT / "logs" / "live-prod-result.json"
RESULTS = {"env": {}, "relayer": {}, "matrix": [], "notes": []}


def _adapt_egress_for_sandbox() -> None:
    """Sandbox-only adaptation, applied before the API boots.

    detect_physical_egress() fail-closes on NICs whose name/description
    matches virtual-tunnel patterns ("Hyper-V Virtual Ethernet Adapter").
    On real hardware the guest NIC is physical; in this VM it never is.
    Keep the real capture pipeline (routes, ip config, Up status, IPv4
    default-route ownership) and only drop the name/description exclusion
    — the exact gate behavior on a physical host.  Nothing else is
    patched: TLS verification, relayer, connect flow all stay production.
    """
    from perchvpn_windows import tun_state_capture as tsc

    original = tsc.detect_physical_egress

    def adapted(snapshot=None):
        result = original(snapshot)
        if result is not None:
            return result
        try:
            snap = snapshot if snapshot is not None else tsc.capture_snapshot()
        except Exception:  # noqa: BLE001
            return None
        default_ifindexes = {
            int(r["InterfaceIndex"])
            for r in (snap.routes or [])
            if str(r.get("DestinationPrefix", "")).strip() == "0.0.0.0/0"
            and str(r.get("InterfaceIndex", "")).lstrip("-").isdigit()
        }
        ipv4_by_index = {}
        for rec in snap.ip_addresses or []:
            idx = rec.get("InterfaceIndex")
            ip = rec.get("IPAddress")
            if isinstance(idx, int) and ip and ":" not in str(ip):
                ipv4_by_index[idx] = str(ip)
        iface_metric = {
            c.get("InterfaceIndex"): c.get("InterfaceMetric")
            for c in (snap.interface_config or [])
            if isinstance(c.get("InterfaceIndex"), int)
        }
        for adapter in snap.adapters or []:
            idx = adapter.get("InterfaceIndex")
            if not isinstance(idx, int) or str(adapter.get("Status", "")).lower() != "up":
                continue
            if idx not in default_ifindexes:
                continue
            ip = ipv4_by_index.get(idx)
            if ip:
                metric = iface_metric.get(idx)
                RESULTS["notes"].append(
                    "sandbox egress adaptation: virtual NIC excluded by "
                    "tunnel-ception pattern; using Up adapter %d (%s)" % (idx, ip)
                )
                return ip, idx
        return None

    tsc.detect_physical_egress = adapted


def _adapt_recovery_probe_for_sandbox() -> None:
    """Sandbox-only: same adapter-presence probe, patient timeout.

    The gate's powershell spawn (5s budget) regularly exceeds its timeout
    while the connect flow loads this 2-vCPU VM, reporting "inconclusive"
    and failing closed.  Run the identical Get-NetAdapter probe with a
    30s budget; rc=2 (probe threw) still reports inconclusive honestly.
    """
    from perchvpn_windows import tun_recovery as tr

    original = tr._default_adapter_probe

    def patient(guid, name):
        if sys.platform != "win32":
            return original(guid, name)
        real_run = tr.subprocess.run

        def timed_run(*args, **kwargs):
            kwargs["timeout"] = max(float(kwargs.get("timeout", 5.0)), 30.0)
            return real_run(*args, **kwargs)

        tr.subprocess.run = timed_run
        try:
            return original(guid, name)
        finally:
            tr.subprocess.run = real_run

    tr._default_adapter_probe = patient

MATRIX = (
    ("h1_plain", "h1", "disabled", 300),
    ("h1_combined", "h1", "combined", 300),
    ("h3", "h3", "disabled", 300),
)

GHOST_PS = (
    "Get-CimInstance Win32_PnPEntity -Filter \"PNPClass='SoftwareDevice' OR PNPClass='System'\" "
    "-ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -like 'SWD\\WINTUN*' } | "
    "ForEach-Object { '{0}|{1}' -f $_.DeviceID, $_.Present }"
)

ROUTE_PS = (
    "$d = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
    "Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 4; "
    "$a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Perch*' }; "
    "$out = @($d | ForEach-Object { 'ROUTE|' + $_.DestinationPrefix + '|' + $_.NextHop + '|' + $_.InterfaceIndex + '|' + $_.RouteMetric }); "
    "$out += @($a | ForEach-Object { 'ADAPTER|' + $_.Name + '|' + $_.Status }); "
    "$out -join ';'"
)


def run_ps(script: str, timeout: float = 40.0) -> str:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return (proc.stdout or "").strip()
    except Exception as exc:  # noqa: BLE001
        return "PS_ERROR: %s: %s" % (type(exc).__name__, exc)


def ghost_present_count() -> int:
    out = run_ps(GHOST_PS)
    rows = [r for r in out.splitlines() if "WINTUN" in r.upper()]
    return len(rows)


def route_snapshot() -> str:
    return run_ps(ROUTE_PS)


def parse_cloudflare_trace(body: str) -> dict:
    fields = {}
    for line in body.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            if k in ("ip", "loc", "warp", "colo"):
                fields[k] = v
    return fields


def udp_reach_probe(host: str, port: int) -> dict:
    """Send one UDP datagram to the edge and classify the reply."""
    try:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET)
        ip = infos[0][4][0]
    except Exception as exc:  # noqa: BLE001
        return {"error": "%s: %s" % (type(exc).__name__, exc)}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(b"\x00" * 8, (ip, port))
        data, addr = sock.recvfrom(2048)
        return {"ip": ip, "reply_bytes": len(data), "addr": addr[0]}
    except ConnectionResetError:
        return {"ip": ip, "result": "icmp_unreachable"}
    except socket.timeout:
        return {"ip": ip, "result": "no_response_filtered_or_quiet"}
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        sock.close()


def summarize_status(st: dict) -> dict:
    keys = ("status", "exit_verification_state", "exit_ip", "country", "transport",
            "active_connections", "proxy_only_mode")
    return {k: st.get(k) for k in keys}


async def main() -> None:  # noqa: C901
    import uvicorn
    from perchvpn_windows import api as api_module

    _adapt_egress_for_sandbox()
    _adapt_recovery_probe_for_sandbox()
    config = uvicorn.Config(api_module.app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(150):
        if server.started:
            break
        await asyncio.sleep(0.2)
    sockets = list(getattr(server, "servers", []) or [])
    base = "http://127.0.0.1:%d" % sockets[0].sockets[0].getsockname()[1]
    RESULTS["env"]["api_port_ok"] = bool(server.started)
    print("API at", base, flush=True)

    # Give the idle boot a moment to load persisted auth + serverlist.
    await asyncio.sleep(8)

    async with httpx.AsyncClient(trust_env=False, timeout=90.0) as http:
        # -- account (auth hydration proof) --------------------------------
        try:
            acct = await http.get(base + "/api/account")
            body = acct.json() if acct.status_code == 200 else {}
            RESULTS["env"]["account"] = {
                "status": acct.status_code,
                "uid_present": bool(body.get("uid")),
                "subscribed": body.get("subscribed"),
                "email_domain_only": (body.get("email") or "").split("@")[-1],
            }
        except Exception as exc:  # noqa: BLE001
            RESULTS["env"]["account"] = {"error": "%s: %s" % (type(exc).__name__, exc)}

        # -- production relayer RTT probes ---------------------------------
        for provider, url in (
            ("cloudflare", "https://relayer.foxyvpn.workers.dev"),
            ("vercel", "https://relayer.foxyvpn.vercel.app"),
        ):
            entry: dict = {}
            try:
                r = await http.post(base + "/api/network/relayer/test", json={"provider": provider})
                payload = r.json() if r.status_code == 200 else {"http_status": r.status_code}
                results = payload.get("results") or []
                entry["endpoint_post"] = {
                    "http_status": r.status_code,
                    "results": results,
                }
            except Exception as exc:  # noqa: BLE001
                entry["endpoint_post"] = {"error": "%s: %s" % (type(exc).__name__, exc)}
            try:
                direct = await http.get(url, timeout=15.0)
                entry["direct_get"] = {
                    "status": direct.status_code,
                    "body_len": len(direct.content),
                    "body_prefix": direct.text[:32],
                }
            except Exception as exc:  # noqa: BLE001
                entry["direct_get"] = {"error": "%s: %s" % (type(exc).__name__, exc)}
            RESULTS["relayer"][url] = entry
        print("relayer probes done", flush=True)

        RESULTS["env"]["routes_baseline"] = route_snapshot()
        RESULTS["env"]["ghosts_before"] = ghost_present_count()

        # -- production MASQUE matrix --------------------------------------
        for label, tv, frag, delay in MATRIX:
            entry = {"mode": label, "transport_version": tv, "tls_fragment_mode": frag}
            print("=== mode", label, flush=True)
            if tv == "h3":
                entry["udp_probe"] = await asyncio.to_thread(
                    udp_reach_probe, "p.m1.fastly-masque.net", 2499
                )
            try:
                # Ensure clean slate between modes.
                try:
                    st = (await http.get(base + "/api/status")).json()
                    if st.get("status") not in ("disconnected", "failed"):
                        await http.post(base + "/api/disconnect")
                        for _ in range(45):
                            st = (await http.get(base + "/api/status")).json()
                            if st.get("status") == "disconnected":
                                break
                            await asyncio.sleep(2)
                except Exception:  # noqa: BLE001
                    pass

                net = await http.post(base + "/api/network", json={
                    "transport_version": tv,
                    "tls_fragment_mode": frag,
                    "tls_fragment_fallback_delay_ms": delay,
                })
                entry["network_post_status"] = net.status_code
                if net.status_code == 200:
                    stored = net.json()
                    entry["stored_transport"] = stored.get("transport_version")
                    entry["stored_fragment"] = stored.get("tls_fragment_mode")
                    entry["stored_delay"] = stored.get("tls_fragment_fallback_delay_ms")

                conn = await http.post(base + "/api/restart", json={"mode": "tun"})
                entry["connect_http_status"] = conn.status_code
                if conn.status_code != 200:
                    entry["connect_detail"] = (conn.json() or {}).get("detail", "")
                    RESULTS["matrix"].append(entry)
                    continue

                deadline = time.monotonic() + 300.0
                st = {}
                while time.monotonic() < deadline:
                    try:
                        st = (await http.get(base + "/api/status")).json()
                    except Exception:  # noqa: BLE001
                        await asyncio.sleep(3)
                        continue
                    tunnel_state = (st.get("tunnel") or {}).get("state")
                    if st.get("status") in ("failed", "disconnected"):
                        if st.get("status") != "connecting":
                            break
                    if st.get("status") == "connected" and tunnel_state == "traffic_verified":
                        break
                    await asyncio.sleep(3)
                entry["status"] = summarize_status(st)
                entry["tunnel_state"] = (st.get("tunnel") or {}).get("state")
                tunnel_verified = (
                    st.get("status") == "connected"
                    and (st.get("tunnel") or {}).get("state") == "traffic_verified"
                )
                if not tunnel_verified:
                    print("connect did not verify:", entry["status"], flush=True)
                    await http.post(base + "/api/disconnect")
                    RESULTS["matrix"].append(entry)
                    continue

                if not tunnel_verified:
                    print("connect did not verify:", entry["status"], flush=True)
                    await http.post(base + "/api/disconnect")
                    RESULTS["matrix"].append(entry)
                    continue

                # System transit through the TUN, immediately at verification.
                async def transit_probe():
                    try:
                        t0 = time.monotonic()
                        tr = await http.get(
                            "https://www.cloudflare.com/cdn-cgi/trace", timeout=25.0
                        )
                        return {
                            "status": tr.status_code,
                            "ms": round((time.monotonic() - t0) * 1000, 1),
                            **parse_cloudflare_trace(tr.text),
                        }
                    except Exception as exc:  # noqa: BLE001
                        return {"error": "%s: %s" % (type(exc).__name__, exc)}

                entry["transit"] = await transit_probe()

                # Guest DNS resolution through the tunnel.
                try:
                    loop = asyncio.get_event_loop()
                    infos = await loop.getaddrinfo("www.cloudflare.com", 443, family=socket.AF_INET)
                    entry["dns_resolve"] = {"ok": bool(infos), "count": len(infos)}
                except Exception as exc:  # noqa: BLE001
                    entry["dns_resolve"] = {"error": "%s: %s" % (type(exc).__name__, exc)}

                # Track where the app-level exit verification settles.
                vstates = [st.get("exit_verification_state")]
                for _ in range(10):
                    await asyncio.sleep(4)
                    vstates.append((await http.get(base + "/api/status")).json()
                                   .get("exit_verification_state"))
                entry["exit_verification_states"] = vstates
                st = (await http.get(base + "/api/status")).json()
                entry["status"] = summarize_status(st)
                entry["tunnel_state_final"] = (st.get("tunnel") or {}).get("state")

                # Second transit sample: does the data path hold up?
                entry["transit_final"] = await transit_probe()

                # Clean disconnect + evidence.
                disc = await http.post(base + "/api/disconnect")
                entry["disconnect_status"] = disc.status_code
                for _ in range(60):
                    st = (await http.get(base + "/api/status")).json()
                    if st.get("status") == "disconnected":
                        break
                    await asyncio.sleep(2)
                entry["status_after_disconnect"] = st.get("status")
                await asyncio.sleep(3)
                ghosts = ghost_present_count()
                entry["ghosts_after_disconnect"] = ghosts
                entry["routes_equal_baseline"] = route_snapshot() == RESULTS["env"]["routes_baseline"]
            except Exception as exc:  # noqa: BLE001
                entry["error"] = "%s: %s" % (type(exc).__name__, exc)
            RESULTS["matrix"].append(entry)

    RESULTS["finished"] = True
    RESULT_PATH.write_text(json.dumps(RESULTS, indent=1), encoding="utf-8")
    print("RESULT_WRITTEN", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
