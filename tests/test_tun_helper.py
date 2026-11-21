"""Tests for the UAC-elevated TUN helper lifecycle (no privileged I/O)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from perchvpn_windows import tun_helper, tun_status


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeProcess:
    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.now += max(0.0, seconds)


def _spec(**overrides):
    values = dict(
        proxy_host="127.0.0.1",
        proxy_port=1080,
        executable=r"C:\bin\sing-box.exe",
        adapter="PerchVPN",
        mtu=1400,
        bypass=["203.0.113.9"],
        extra_args=[],
        parent_pid=1234,
    )
    values.update(overrides)
    return tun_helper.TunHelperSpec(**values)


def _evidence(up=True, default_route=True, present=True):
    routes = []
    if default_route:
        routes = [{"destination_prefix": "0.0.0.0/0"}]
    return tun_status.AdapterEvidence(
        present=present,
        up=up,
        if_index=41,
        ipv4=["10.7.0.2"] if present else [],
        routes=routes,
    )


def _snapshot(**kw):
    from perchvpn_windows.tun_state_capture import NetworkSnapshot

    return NetworkSnapshot(**kw)


def _adapter(name, index, status="Up", guid=None):
    return {
        "Name": name,
        "InterfaceGuid": guid or ("guid-%s" % name),
        "InterfaceDescription": name,
        "InterfaceIndex": index,
        "Status": status,
    }


def _default_route(index=1, next_hop="192.168.1.1"):
    return {
        "DestinationPrefix": "0.0.0.0/0",
        "NextHop": next_hop,
        "InterfaceIndex": index,
        "RouteMetric": 0,
        "PolicyStore": "ActiveStore",
    }


def _ip(index, address):
    return {
        "InterfaceIndex": index,
        "IPAddress": address,
        "PrefixLength": 24,
        "AddressFamily": 2,
    }


def _iface(index, metric=10):
    return {
        "InterfaceIndex": index,
        "AddressFamily": 2,
        "InterfaceMetric": metric,
        "ConnectionState": 1,
    }


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestSidecarCommand:
    def test_setup_and_adapter_are_requested(self, tmp_path):
        config_path = tmp_path / "sing-box.json"
        cmd = tun_helper.build_sidecar_command(_spec(), config_path=config_path)
        assert cmd[0].endswith("sing-box.exe")
        assert cmd[-3:] == ["run", "-c", str(config_path)]
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        tun = cfg["inbounds"][0]
        assert tun["interface_name"] == "PerchVPN"
        assert tun["mtu"] == 1400
        assert tun["auto_route"] is True
        assert "203.0.113.9/32" in tun["route_exclude_address"]
        socks = next(o for o in cfg["outbounds"] if o["type"] == "socks")
        assert socks["server"] == "127.0.0.1"
        assert socks["server_port"] == 1080

    def test_extra_args_are_preserved(self):
        cmd = tun_helper.build_sidecar_command(_spec(extra_args=["--foo", "bar"]))
        assert cmd[1:3] == ["--foo", "bar"]

    def test_chained_mode_never_requests_setup(self, tmp_path):
        """auto_route would install 0.0.0.0/0 and collide with the underlay."""
        config_path = tmp_path / "sing-box.json"
        cmd = tun_helper.build_sidecar_command(
            _spec(), config_path=config_path, setup=False
        )
        assert "--setup" not in cmd
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
        assert cfg["inbounds"][0]["auto_route"] is False
        assert cfg["inbounds"][0]["strict_route"] is False


# ---------------------------------------------------------------------------
# Conflict detection / prerequisites
# ---------------------------------------------------------------------------


class TestConflictDetection:
    def test_foreign_tunnel_owning_default_route_conflicts(self):
        snap = _snapshot(
            routes=[_default_route(56)],
            adapters=[
                _adapter("Ethernet", 7),
                _adapter("singbox_tun", 56, guid="foreign"),
            ],
        )
        assert tun_helper.detect_tunnel_conflict(snap, "PerchVPN") == "singbox_tun"

    def test_physical_default_route_is_not_a_conflict(self):
        snap = _snapshot(
            routes=[_default_route(7)],
            adapters=[_adapter("Ethernet", 7), _adapter("Wi-Fi", 9)],
        )
        assert tun_helper.detect_tunnel_conflict(snap, "PerchVPN") is None

    def test_own_adapter_never_conflicts(self):
        snap = _snapshot(
            routes=[_default_route(41)],
            adapters=[_adapter("PerchVPN", 41)],
        )
        assert tun_helper.detect_tunnel_conflict(snap, "PerchVPN") is None


class TestPrerequisites:
    def _check(self, **kwargs):
        base = dict(
            executable_path=r"C:\bin\sing-box.exe",
            sidecar_resolver=lambda p: p,
            elevated=False,
            helper_can_elevate=True,
            snapshot=_snapshot(
                routes=[_default_route(7)],
                adapters=[_adapter("Ethernet", 7)],
                ip_addresses=[_ip(7, "198.51.100.5")],
                interface_config=[_iface(7)],
            ),
        )
        base.update(kwargs)
        return tun_helper.check_prerequisites(**base)

    def test_allows_non_elevated_gui_when_helper_can_elevate(self):
        report = self._check()
        assert report.ok, report.detail
        assert report.physical_ip == "198.51.100.5"

    def test_foreign_tunnel_coexists_instead_of_refusing(self):
        snap = _snapshot(
            routes=[_default_route(56), _default_route(7)],
            adapters=[_adapter("Ethernet", 7), _adapter("singbox_tun", 56)],
            ip_addresses=[_ip(7, "198.51.100.5")],
            interface_config=[_iface(7)],
        )
        report = self._check(snapshot=snap)
        assert report.ok
        assert report.code == "coexist"
        assert report.adapter_conflict == "singbox_tun"

    def test_refuses_without_elevation_or_helper(self):
        report = self._check(helper_can_elevate=False)
        assert not report.ok
        assert report.code == "elevation_unavailable"

    def test_refuses_unowned_existing_adapter(self):
        snap = _snapshot(
            routes=[_default_route(7)],
            adapters=[_adapter("Ethernet", 7), _adapter("PerchVPN", 41)],
            ip_addresses=[_ip(7, "198.51.100.5")],
            interface_config=[_iface(7)],
        )
        report = self._check(snapshot=snap)
        assert not report.ok
        assert report.code == "adapter_owned_by_other"

    def test_requires_opt_in(self):
        report = self._check(opt_in=False)
        assert not report.ok
        assert report.code == "opt_in_required"


# ---------------------------------------------------------------------------
# Helper runtime
# ---------------------------------------------------------------------------


class FakeHostRoutes:
    """Minimal read-only model of the Windows route table for the helper.

    Tracks only routes the helper installs, so read-back verification can be
    exercised: ``New-NetRoute`` records, ``Remove-NetRoute`` forgets, and the
    identity probes report what the fake table actually contains.  IPv4 and
    IPv6 are modelled separately so leak-prevention can be asserted.
    """

    def __init__(self):
        self.split = {}  # prefix -> metric (IPv4, PerchVPN adapter)
        self.split6 = {}  # prefix -> metric (IPv6, PerchVPN adapter)
        self.pins = {}  # (prefix, index) -> (next_hop, metric), IPv4
        self.pins6 = {}  # (prefix, index) -> (next_hop, metric), IPv6
        self.adapter_metric = 10
        self.adapter_metric6 = 10
        self.host_ipv6 = False
        self.dns = {}  # interface index -> [server addresses]
        self.dns_flushes = 0
        self.removals = []
        self.adapter_address = None  # IPv4 assigned to the PerchVPN adapter
        self.address_installs = []
        self.physical_index = 7
        self.interface_for = {}  # destination -> interface index override

    @staticmethod
    def _family(prefix: str) -> str:
        return "IPv6" if ":" in prefix else "IPv4"

    def _split_store(self, prefix: str):
        return self.split6 if ":" in prefix else self.split

    def _pin_store(self, prefix: str):
        return self.pins6 if ":" in prefix else self.pins

    def __call__(self, script: str) -> str:
        import re

        if "Get-NetRoute -DestinationPrefix '::/0'" in script:
            if "-InterfaceIndex 7" in script:
                return "fe80::1" if self.host_ipv6 else ""
            return "yes" if self.host_ipv6 else "no"
        if "Clear-DnsClientCache" in script:
            self.dns_flushes += 1
            return ""
        if "Get-DnsClientServerAddress" in script:
            index = int(re.search(r"-InterfaceIndex (\d+)", script).group(1))
            servers = list(self.dns.get(index) or [])
            if "-AddressFamily IPv4" in script:
                servers = [v for v in servers if ":" not in v]
            elif "-AddressFamily IPv6" in script:
                servers = [v for v in servers if ":" in v]
            return json.dumps(servers) if servers else ""
        if "Set-DnsClientServerAddress" in script:
            index = int(re.search(r"-InterfaceIndex (\d+)", script).group(1))
            if "-ResetServerAddresses" in script:
                self.dns.pop(index, None)
                return ""
            body = re.search(r"-ServerAddresses @\((.*?)\)", script)
            servers = re.findall(r"'([^']+)'", body.group(1)) if body else []
            existing = list(self.dns.get(index) or [])
            for family in ("v4", "v6"):
                new = [v for v in servers if (":" in v) == (family == "v6")]
                if new:
                    existing = [
                        v for v in existing if (":" in v) != (family == "v6")
                    ] + new
            self.dns[index] = existing
            return ""
        if "Set-NetIPInterface" in script:
            metric = int(re.search(r"-InterfaceMetric (\d+)", script).group(1))
            if "AddressFamily IPv6" in script:
                self.adapter_metric6 = metric
            else:
                self.adapter_metric = metric
            return ""
        if "Get-NetIPAddress" in script or "New-NetIPAddress" in script:
            if "New-NetIPAddress" in script and not self.adapter_address:
                match = re.search(r"-IPAddress '([^']+)'", script)
                self.adapter_address = match.group(1) if match else "10.0.0.1"
                self.address_installs.append(self.adapter_address)
            return self.adapter_address or ""
        if "Remove-NetRoute" in script:
            prefix = re.search(r"-DestinationPrefix '([^']+)'", script).group(1)
            index = re.search(r"-InterfaceIndex (\d+)", script)
            alias = re.search(r"-InterfaceAlias '([^']+)'", script)
            self.removals.append(script)
            if index:
                self._pin_store(prefix).pop((prefix, int(index.group(1))), None)
            if alias:
                self._split_store(prefix).pop(prefix, None)
            return ""
        if "New-NetRoute" in script:
            prefix = re.search(r"-DestinationPrefix '([^']+)'", script).group(1)
            metric = int(re.search(r"-RouteMetric (\d+)", script).group(1))
            index = re.search(r"-InterfaceIndex (\d+)", script)
            alias = re.search(r"-InterfaceAlias '([^']+)'", script)
            hop = re.search(r"-NextHop '([^']+)'", script)
            if alias:
                self._split_store(prefix)[prefix] = metric
            else:
                self._pin_store(prefix)[(prefix, int(index.group(1)))] = (
                    hop.group(1) if hop else "0.0.0.0",
                    metric,
                )
            return ""
        if "Set-NetRoute" in script:
            prefix = re.search(r"-DestinationPrefix '([^']+)'", script).group(1)
            self._split_store(prefix)[prefix] = int(
                re.search(r"-RouteMetric (\d+)", script).group(1)
            )
            return ""
        if "Find-NetRoute" in script:
            ip = re.search(r"-RemoteIPAddress '([^']+)'", script).group(1)
            if "if ($r) { $r.InterfaceIndex }" in script:
                return str(self.interface_for.get(ip, self.physical_index))
            if ":" in ip:
                if (ip + "/128", 7) in self.pins6:
                    # A pinned /128 is more specific than the TUN's ::/1.
                    return "7|Ethernet"
                return "41|PerchVPN" if self.host_ipv6 else "7|Ethernet"
            if ip in tun_helper._ROUTE_SELECTION_PROBES:
                return "41|PerchVPN"
            for (prefix, index) in self.pins:
                if prefix == ip + "/32":
                    return "%d|pin" % index
            return "7|Ethernet"
        if "Get-NetIPInterface" in script:
            return str(
                self.adapter_metric6 if "AddressFamily IPv6" in script else self.adapter_metric
            )
        if "Get-NetAdapter" in script:
            alias = re.search(r"-InterfaceAlias '([^']+)'", script)
            index = re.search(r"-InterfaceIndex (\d+)", script)
            if "if (Get-NetAdapter" in script:
                return "present"
            if alias and alias.group(1) == "PerchVPN":
                return "guid-PerchVPN"
            if alias and alias.group(1) == "singbox_tun":
                return "guid-singbox"
            if index and index.group(1) == "41":
                return "guid-PerchVPN"
            if index and index.group(1) == "56":
                return "guid-singbox"
            if (alias and alias.group(1) == "Ethernet") or (
                index and index.group(1) == "7"
            ):
                return "guid-Ethernet"
            return ""
        if "Get-NetRoute" in script:
            prefix = re.search(r"-DestinationPrefix '([^']+)'", script).group(1)
            alias = re.search(r"-InterfaceAlias '([^']+)'", script)
            index = re.search(r"-InterfaceIndex (\d+)", script)
            store = self._split_store(prefix)
            if alias:
                if "ConvertTo-Json" in script:
                    return ('"%s"' % prefix) if prefix in store else ""
                if prefix not in store:
                    return ""
                return "0.0.0.0|%d|41" % store[prefix]
            if index:
                pins = self._pin_store(prefix)
                key = (prefix, int(index.group(1)))
                if "if (Get-NetRoute" in script:
                    return "present" if key in pins else "absent"
                if key not in pins:
                    return ""
                hop, metric = pins[key]
                return "%s|%d|%d" % (hop, metric, key[1])
            return ""
        return ""


class TestRunHelper:
    # A realistic physical NIC snapshot: Ethernet (ifIndex 7) owns the
    # IPv4 default route and the egress address, so the helper's read-only
    # physical-egress autodetect and /32 pinning can be exercised without
    # any privileged I/O.
    PHYSICAL_SNAPSHOT = _snapshot(
        routes=[_default_route(7)],
        adapters=[_adapter("Ethernet", 7)],
        ip_addresses=[_ip(7, "198.51.100.5")],
        interface_config=[_iface(7, metric=10)],
    )

    def _run(
        self,
        tmp_path,
        monkeypatch,
        *,
        probe,
        parent_alive=None,
        capture=None,
        compare=None,
        host=None,
        spawn=None,
        bypass_path=None,
        terminate=None,
        spec=None,
        stop_path=None,
    ):
        monkeypatch.setattr(
            tun_helper, "compare_snapshots", compare or (lambda a, b: [])
        )
        commands = []
        host = host or FakeHostRoutes()
        helper_spec = spec or _spec()
        base_capture = capture or (lambda: self.PHYSICAL_SNAPSHOT)

        def staged_capture():
            snap = base_capture()
            if not spawned:
                # Before the sidecar starts the PerchVPN adapter must not exist.
                return snap
            return _snapshot(
                routes=list(snap.routes) + [_default_route(41)],
                adapters=list(snap.adapters)
                + [_adapter("PerchVPN", 41, guid="guid-PerchVPN")],
                ip_addresses=list(snap.ip_addresses) + [_ip(41, "10.7.0.2")],
                interface_config=list(snap.interface_config) + [_iface(41, metric=1)],
            )

        def fake_run_ps(script: str) -> str:
            commands.append(script)
            return host(script)

        monkeypatch.setattr(tun_helper, "_run_powershell", fake_run_ps)
        clock = FakeClock()
        proc = FakeProcess()
        spawned = []

        def do_spawn(cmd):
            spawned.append(list(cmd))
            if spawn is not None:
                return spawn(cmd)
            return proc

        def default_parent_alive(pid):
            try:
                current = json.loads((tmp_path / "state.json").read_text())
            except (OSError, ValueError):
                return True
            return current.get("phase") != tun_helper.PHASE_READY

        async def run():
            return await tun_helper.run_helper(
                helper_spec,
                state_path=tmp_path / "state.json",
                stop_path=stop_path or (tmp_path / "stop"),
                journal=tmp_path / "journal.json",
                bypass_path=bypass_path,
                spawn=do_spawn,
                probe=probe,
                capture=staged_capture,
                egress=lambda: {"ipv4": {"ip": "203.0.113.50"}},
                sleep=clock.sleep,
                clock=clock,
                parent_alive=parent_alive or default_parent_alive,
                terminate=terminate or (lambda p: p.terminate()),
                startup_timeout=5.0,
                poll_interval=1.0,
            )

        return asyncio.run(run()), proc, spawned, commands, clock

    def test_publishes_starting_state_before_baseline_capture(
        self, tmp_path, monkeypatch
    ):
        seen = {}

        def capture():
            seen.update(json.loads((tmp_path / "state.json").read_text()))
            raise RuntimeError("capture would block")

        async def probe(adapter):
            return _evidence()

        final, _proc, _spawned, _commands, _clock = self._run(
            tmp_path, monkeypatch, probe=probe, capture=capture
        )
        assert seen["phase"] == tun_helper.PHASE_STARTING
        assert seen["pid"]
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "capture would block" in final["error"]

    def test_run_helper_uses_preferred_capture_and_publishes_timings(
        self, tmp_path, monkeypatch
    ):
        import inspect

        default = inspect.signature(tun_helper.run_helper).parameters["capture"].default
        assert default is tun_helper.capture_snapshot_preferred

        async def probe(adapter):
            return _evidence()

        final, _proc, _spawned, _commands, _clock = self._run(
            tmp_path, monkeypatch, probe=probe
        )
        timings = final["timings"]
        for key in (
            "capture_seconds",
            "config_seconds",
            "spawn_seconds",
            "sidecar_seconds",
            "total_seconds",
        ):
            assert key in timings
            assert timings[key] >= 0

    def test_ready_then_parent_exit_stops_and_clears_journal(self, tmp_path, monkeypatch):
        calls = {"n": 0}

        async def probe(adapter):
            calls["n"] += 1
            return _evidence()

        final, proc, spawned, commands, clock = self._run(tmp_path, monkeypatch, probe=probe)
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert proc.terminated
        assert spawned[0][-3:] == ["run", "-c", spawned[0][-1]]
        assert calls["n"] >= 1
        journal = tmp_path / "journal.json"
        assert not journal.exists()
        # sing-box owns routing table and exclusions through auto_route.
        cfg = json.loads(Path(spawned[0][-1]).read_text(encoding="utf-8"))
        assert cfg["inbounds"][0]["auto_route"] is True
        assert cfg["inbounds"][0]["strict_route"] is True
        assert "203.0.113.9/32" in cfg["inbounds"][0]["route_exclude_address"]

    def test_teardown_journals_stopping_before_child_exit_and_pin_removal(
        self, tmp_path, monkeypatch
    ):
        """A stop must persist the intent to tear down before the blocking
        child wait, then remove the physical /32 pin, so an app exit during
        sing-box shutdown can still recover stale routes next time."""
        host = FakeHostRoutes()
        journal_path = tmp_path / "journal.json"
        seen = {}

        def terminate_and_capture(proc):
            seen["phase"] = json.loads(journal_path.read_text())["phase"]
            proc.terminate()

        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            host=host,
            terminate=terminate_and_capture,
        )
        assert seen["phase"] == tun_helper.PHASE_STOPPING
        assert proc.terminated
        assert ("203.0.113.9/32", 7) not in host.pins
        assert final["phase"] == tun_helper.PHASE_STOPPED, final.get("error")
        assert not journal_path.exists()

    def test_physical_bypass_route_is_journaled_and_removed(self, tmp_path, monkeypatch):
        host = FakeHostRoutes()
        host.pins[("198.51.100.5/32", 7)] = ("192.168.1.1", 1)
        spec = _spec(bypass=["203.0.113.9", "198.51.100.5"])
        seen = {}
        proc = FakeProcess()
        journal_path = tmp_path / "journal.json"

        def spawn(cmd):
            seen["journal"] = json.loads(journal_path.read_text())
            return proc

        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            host=host,
            spec=spec,
            spawn=spawn,
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final
        cfg = json.loads(Path(spawned[0][-1]).read_text(encoding="utf-8"))
        assert "198.51.100.5/32" in cfg["inbounds"][0]["route_exclude_address"]
        assert "203.0.113.9/32" in cfg["inbounds"][0]["route_exclude_address"]

    def test_owner_pid_is_watched_instead_of_parent(self, tmp_path, monkeypatch):
        checked = []
        spec = _spec(owner_pid=9876)
        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            spec=spec,
            parent_alive=lambda pid: checked.append(pid) or False,
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert 9876 in checked
        assert 1234 not in checked

    def test_helper_does_not_install_split_routes(self, tmp_path, monkeypatch):
        """sing-box's auto_route owns the split routes; the helper must not
        race it with duplicate New-NetRoute or metric rewrites."""
        host = FakeHostRoutes()
        host.split = {"0.0.0.0/1": 1, "128.0.0.0/1": 1}
        final, proc, spawned, commands, clock = self._run(
            tmp_path, monkeypatch, probe=lambda a: _evidence(), host=host
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final
        joined = "\n".join(commands)
        assert "New-NetRoute -DestinationPrefix '0.0.0.0/1'" not in joined
        assert "New-NetRoute -DestinationPrefix '128.0.0.0/1'" not in joined
        assert "Set-NetRoute -DestinationPrefix '0.0.0.0/1'" not in joined
        assert "Set-NetIPInterface -InterfaceAlias 'PerchVPN'" not in joined
        assert spawned[0][-3:] == ["run", "-c", spawned[0][-1]]

    def _underlay_snapshot(self):
        return _snapshot(
            routes=[_default_route(56), _default_route(7)],
            adapters=[
                _adapter("Ethernet", 7),
                _adapter("singbox_tun", 56, guid="guid-singbox"),
            ],
            ip_addresses=[_ip(7, "198.51.100.5")],
            interface_config=[_iface(7), _iface(56, metric=5)],
        )

    def test_foreign_tunnel_is_never_the_carrier(self, tmp_path, monkeypatch):
        """A running anti-censorship tunnel is ignored: PerchVPN pins its
        upstream on the physical NIC's own gateway and installs /1 routes."""
        host = FakeHostRoutes()
        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            capture=self._underlay_snapshot,
            host=host,
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final.get("error")
        assert final["physical"]["adapter"] == "Ethernet"
        assert final["physical"]["interface_index"] == 7
        assert final["physical"]["gateway"] == "192.168.1.1"
        assert final.get("coexisting_with") == "singbox_tun"
        assert final.get("dns_policy") == "perchvpn"
        assert spawned[0][-3:] == ["run", "-c", spawned[0][-1]]

    def test_virtual_only_egress_is_refused(self, tmp_path, monkeypatch):
        """If the only egress belongs to a virtual adapter, activation fails
        before any privileged mutation instead of chaining over it."""
        host = FakeHostRoutes()
        snap = _snapshot(
            routes=[_default_route(7, next_hop="172.28.0.1")],
            adapters=[
                _adapter("vEthernet (Default Switch)", 7, guid="guid-hyperv")
            ],
            ip_addresses=[_ip(7, "172.28.0.1")],
            interface_config=[_iface(7, metric=5)],
        )
        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            capture=lambda: snap,
            host=host,
        )
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "no physical" in final["error"]
        assert spawned == []
        assert not any("New-NetRoute" in c for c in commands)
        assert not any("New-NetIPAddress" in c for c in commands)

    def test_no_physical_egress_is_refused(self, tmp_path, monkeypatch):
        """Without any physical egress IPv4 TUN fails closed."""
        snap = _snapshot(
            routes=[_default_route(56, next_hop="172.18.0.2")],
            adapters=[_adapter("singbox_tun", 56)],
            ip_addresses=[],
        )
        final, proc, spawned, commands, clock = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            capture=lambda: snap,
        )
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "no physical" in final["error"]
        assert spawned == []
        assert not any("New-NetRoute" in c for c in commands)

    def test_physical_layout_is_unchanged_without_underlay(self, tmp_path, monkeypatch):
        """No underlay: pins on the physical NIC and /1 split routes remain."""
        snap = _snapshot(
            routes=[_default_route(7)],
            adapters=[_adapter("Ethernet", 7), _adapter("singbox_tun", 56)],
            ip_addresses=[_ip(7, "198.51.100.5")],
            interface_config=[_iface(7), _iface(56, metric=5)],
        )
        final, proc, spawned, commands, clock = self._run(
            tmp_path, monkeypatch, probe=lambda a: _evidence(), capture=lambda: snap
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final
        assert final["physical"]["adapter"] == "Ethernet"
        assert spawned[0][-3:] == ["run", "-c", spawned[0][-1]]

    def test_partial_setup_failure_undoes_pins_and_reports_exact_error(self, tmp_path, monkeypatch):
        def failing_spawn(cmd):
            raise OSError("access denied")

        final, proc, spawned, commands, _ = self._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            spawn=failing_spawn,
            spec=_spec(bypass=["203.0.113.9", "198.51.100.10"]),
        )
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "sidecar spawn failed" in final["error"]
        assert "access denied" in final["error"]
        assert len(spawned) == 1

    def test_partial_startup_fails_closed_and_terminates(self, tmp_path, monkeypatch):
        async def probe(adapter):
            return _evidence(up=False)

        final, proc, spawned, commands, _ = self._run(tmp_path, monkeypatch, probe=probe)
        assert final["phase"] == tun_helper.PHASE_FAILED
        # Stage-1 honesty: the adapter itself never became usable.
        assert "did not come up with an IPv4 address within" in final["error"]
        assert proc.terminated

    def test_residual_state_is_recovery_required(self, tmp_path, monkeypatch):
        from perchvpn_windows.tun_state_capture import StateDifference

        async def probe(adapter):
            return _evidence()

        diffs = [StateDifference(category="route", description="route added: 10.0.0.0/8")]
        final, _, _, _, _ = self._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            compare=lambda a, b: list(diffs),
        )
        assert final["phase"] == tun_helper.PHASE_RECOVERY
        assert final["residual"] == ["route: route added: 10.0.0.0/8"]
        assert (tmp_path / "journal.json").exists()

    def test_stop_file_cleans_up_without_residuals(self, tmp_path, monkeypatch):
        stop = tmp_path / "stop"
        stop.write_text("stop")
        final, proc, spawned, commands, _ = self._run(
            tmp_path, monkeypatch, probe=lambda a: _evidence(), stop_path=stop
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert final["stop_reason"] == "stop-request"
        assert spawned == []
        assert not proc.terminated
        assert not (tmp_path / "journal.json").exists()

    def test_stop_file_during_startup_cancels_sidecar_and_clears_journal(
        self, tmp_path, monkeypatch
    ):
        stop = tmp_path / "stop"

        def probe(adapter):
            stop.write_text("stop")
            return _evidence()

        final, proc, spawned, commands, _ = self._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            stop_path=stop,
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert final["stop_reason"] == "stop-request"
        assert spawned
        assert proc.terminated
        assert not (tmp_path / "journal.json").exists()

    def test_parent_exit_during_startup_cancels_sidecar_and_clears_journal(
        self, tmp_path, monkeypatch
    ):
        started = {"value": False}

        def probe(adapter):
            started["value"] = True
            return _evidence()

        final, proc, spawned, commands, _ = self._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            parent_alive=lambda pid: not started["value"],
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert final["stop_reason"] == "parent-exited"
        assert spawned
        assert proc.terminated
        assert not (tmp_path / "journal.json").exists()


# ---------------------------------------------------------------------------
# GUI-side client
# ---------------------------------------------------------------------------


def test_shell_execute_runas_quotes_spec_path_with_spaces(monkeypatch):
    """A non-elevated launch must preserve a OneDrive-style install path.

    ``lpFile`` is the frozen executable and ``lpParameters`` carries the
    spec path through ``list2cmdline`` quoting; a regression here makes UAC
    silently run the wrong command or reject the helper argument.
    """
    import subprocess
    from types import SimpleNamespace

    captured = {}

    class FakeShell32:
        def ShellExecuteExW(self, sei_ptr):
            sei = sei_ptr._obj
            captured["verb"] = sei.lpVerb
            captured["file"] = sei.lpFile
            captured["params"] = sei.lpParameters
            sei.hProcess = None
            return 1

    class FakeKernel32:
        def GetProcessId(self, handle):
            return 0

        def CloseHandle(self, handle):
            return 1

    monkeypatch.setattr(tun_helper.sys, "platform", "win32")
    monkeypatch.setattr(
        tun_helper.ctypes,
        "windll",
        SimpleNamespace(shell32=FakeShell32(), kernel32=FakeKernel32()),
        raising=False,
    )

    exe = r"C:\Users\alice\OneDrive - Example\PerchVPN\PerchVPN.exe"
    spec = r"C:\Users\alice\OneDrive - Example\PerchVPN\tun-helper\spec.json"
    result = tun_helper._shell_execute_runas([exe, "--tun-helper", spec])

    assert result["ok"] is True
    assert captured["verb"] == "runas"
    assert captured["file"] == exe
    assert captured["params"] == subprocess.list2cmdline(["--tun-helper", spec])
    assert captured["params"].startswith('--tun-helper "')


class TestTunHelperClient:
    def test_cancelled_uac_is_reported_as_cancelled(self, tmp_path):
        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=tmp_path / "state.json",
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=lambda path: {
                "launched": False,
                "pid": 0,
                "cancelled": True,
                "error": "UAC cancelled",
            },
            sleep=FakeClock().sleep,
            clock=FakeClock(),
        )
        state = asyncio.run(client.start(timeout=2.0))
        assert state["phase"] == tun_helper.PHASE_CANCELLED

    def test_start_acknowledges_ipc_before_ready(self, tmp_path):
        state_path = tmp_path / "state.json"

        def launcher(path):
            state_path.write_text(json.dumps({"phase": "starting", "pid": 77}))
            return {"launched": True, "pid": 77, "cancelled": False, "error": ""}

        class ReadyAfterTwoPolls:
            def __init__(self):
                self.calls = 0

            async def sleep(self, seconds):
                self.calls += 1
                if self.calls >= 2:
                    state_path.write_text(
                        json.dumps({"phase": "ready", "pid": 77, "child_pid": 99})
                    )

        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=ReadyAfterTwoPolls().sleep,
            clock=FakeClock(),
        )
        started = asyncio.run(client.start(timeout=2.0))
        assert client.launch_info["ipc_ready"] is True
        assert client.launch_info["helper_pid"] == 77
        assert started["phase"] == "ready"

    def test_is_running_excludes_terminal_states(self, tmp_path):
        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=tmp_path / "state.json",
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
        )
        for phase in ("starting", "ready", "stopping"):
            (tmp_path / "state.json").write_text(json.dumps({"phase": phase}))
            assert client.is_running() is True
        for phase in ("failed", "stopped", "cancelled", "recovery_required"):
            (tmp_path / "state.json").write_text(json.dumps({"phase": phase}))
            assert client.is_running() is False

    def test_start_reads_ready_state_and_stop_confirms(self, tmp_path):
        state_path = tmp_path / "state.json"
        stop_path = tmp_path / "stop"

        def launcher(path):
            state_path.write_text(json.dumps({"phase": "ready", "child_pid": 99}))
            return {"launched": True, "pid": 99, "cancelled": False, "error": ""}

        class StopSim:
            def __init__(self):
                self.calls = 0

            async def sleep(self, seconds):
                self.calls += 1
                if stop_path.exists():
                    state_path.write_text(json.dumps({"phase": "stopped"}))

        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=stop_path,
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=StopSim().sleep,
            clock=FakeClock(),
        )
        started = asyncio.run(client.start(timeout=2.0))
        assert started["phase"] == "ready"
        stopped = asyncio.run(client.stop(timeout=2.0))
        assert stopped["phase"] == "stopped"
        assert stop_path.exists()

    def test_snapshot_refreshes_after_helper_publishes_egress(self, tmp_path):
        state_path = tmp_path / "state.json"

        def launcher(path):
            state_path.write_text(json.dumps({"phase": "ready", "child_pid": 99}))
            return {"launched": True, "pid": 99, "cancelled": False, "error": ""}

        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=FakeClock().sleep,
            clock=FakeClock(),
        )
        started = asyncio.run(client.start(timeout=2.0))
        assert "system_egress" not in started
        state_path.write_text(
            json.dumps(
                {
                    "phase": "ready",
                    "child_pid": 99,
                    "system_egress": {"ok": True, "error": None},
                }
            )
        )
        assert client.snapshot()["system_egress"] == {"ok": True, "error": None}

    def test_start_skips_dead_stopped_helper_before_relaunch(
        self, tmp_path, monkeypatch
    ):
        state_path = tmp_path / "state.json"
        state_path.write_text(
            json.dumps({"phase": "stopped", "pid": 4242, "stop_reason": "stop-request"})
        )
        terminated = []
        launched = []

        def launcher(path):
            launched.append(path)
            state_path.write_text(json.dumps({"phase": "ready", "pid": 5252}))
            return {"launched": True, "pid": 5252, "cancelled": False, "error": ""}

        monkeypatch.setattr(tun_helper, "_parent_alive", lambda pid: False)
        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=FakeClock().sleep,
            clock=FakeClock(),
            terminator=lambda pid, image: terminated.append(pid) or True,
        )
        state = asyncio.run(client.start(timeout=2.0))
        assert state["phase"] == "ready"
        assert terminated == []
        assert len(launched) == 1

    def test_start_terminates_stale_failed_helper_before_relaunch(self, tmp_path):
        """A failed/recovery helper can still be alive and own the adapter."""
        state_path = tmp_path / "state.json"
        state_path.write_text(
            json.dumps({"phase": "failed", "pid": 4242, "error": "old"})
        )
        terminated = []
        launched = []

        def launcher(path):
            launched.append(path)
            state_path.write_text(json.dumps({"phase": "ready", "pid": 5252}))
            return {"launched": True, "pid": 5252, "cancelled": False, "error": ""}

        clock = FakeClock()
        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=clock.sleep,
            clock=clock,
            terminator=lambda pid, image: terminated.append(pid) or True,
        )
        state = asyncio.run(client.start(timeout=2.0))
        assert state["phase"] == "ready"
        assert terminated == [4242]
        assert len(launched) == 1

    def test_stop_force_terminates_helper_that_ignores_stop_file(self, tmp_path):
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps({"phase": "ready", "pid": 777}))
        terminated = []

        clock = FakeClock()
        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            sleep=clock.sleep,
            clock=clock,
            terminator=lambda pid, image: terminated.append(pid) or True,
        )
        state = asyncio.run(client.stop(timeout=0.05))
        assert terminated == [777]
        assert state["phase"] == "stopped"
        assert state["stop_reason"] == "force-terminated"

    def test_start_replaces_zombie_helper_when_ipc_never_appears(self, tmp_path):
        launches = []
        terminated = []
        clock = FakeClock()

        def launcher(path):
            launches.append(path)
            return {
                "launched": True,
                "pid": 9000 + len(launches),
                "cancelled": False,
                "error": "",
            }

        client = tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=tmp_path / "state.json",
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            launcher=launcher,
            sleep=clock.sleep,
            clock=clock,
            terminator=lambda pid, image: terminated.append(pid) or True,
        )
        state = asyncio.run(client.start(timeout=1.0))
        assert state["phase"] == tun_helper.PHASE_FAILED
        assert "acknowledge IPC" in state["error"]
        assert len(launches) == 2
        assert terminated == [9001, 9002]


class TestAdapterReusePlan:
    def test_healthy_canonical_adapter_is_reused(self):
        snap = _snapshot(
            adapters=[_adapter("PerchVPN", 41, guid="guid-PerchVPN")],
            ip_addresses=[_ip(41, "10.7.0.2")],
        )
        plan = tun_helper.adapter_reuse_plan(snap, "PerchVPN")
        assert plan["action"] == "reuse"
        assert plan["guid"] == "guid-PerchVPN"

    def test_down_adapter_is_replaced(self):
        snap = _snapshot(
            adapters=[_adapter("PerchVPN", 41, status="Down", guid="guid-PerchVPN")],
        )
        plan = tun_helper.adapter_reuse_plan(snap, "PerchVPN")
        assert plan["action"] == "replace"

    def test_journal_guid_mismatch_forces_replacement(self):
        snap = _snapshot(
            adapters=[_adapter("PerchVPN", 41, guid="guid-new")],
            ip_addresses=[_ip(41, "10.7.0.2")],
        )
        journal = {
            "adapter": "PerchVPN",
            "adapter_guid": "guid-old",
            "phase": tun_helper.PHASE_READY,
        }
        plan = tun_helper.adapter_reuse_plan(snap, "PerchVPN", journal)
        assert plan["action"] == "replace"

    def test_foreign_adapter_with_same_name_is_never_touched(self):
        record = _adapter("PerchVPN", 41, guid="guid-foreign")
        record["InterfaceDescription"] = "Intel(R) Ethernet Connection"
        snap = _snapshot(
            adapters=[record],
            ip_addresses=[_ip(41, "10.0.0.2")],
        )
        plan = tun_helper.adapter_reuse_plan(snap, "PerchVPN")
        assert plan["action"] == "foreign"


class TestStaleWintunCleanup:
    def test_non_windows_is_a_noop(self, monkeypatch):
        monkeypatch.setattr(tun_helper.sys, "platform", "linux")
        result = tun_helper.cleanup_stale_wintun_adapters(
            "PerchVPN", run_ps=lambda script: pytest.fail("must not run")
        )
        assert result["remaining"] == 0
        assert result["removed"] == []
        assert result["skipped"] == "not Windows"

    def test_removes_non_present_matching_pnp_nodes(self, monkeypatch):
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        scripts = []

        def run_ps(script):
            scripts.append(script)
            return json.dumps({
                "removed": ["SWD\\WINTUN\\0000"],
                "remaining": 0,
            })

        result = tun_helper.cleanup_stale_wintun_adapters(
            "PerchVPN", run_ps=run_ps
        )

        assert result == {"removed": ["SWD\\WINTUN\\0000"], "remaining": 0}
        assert "pnputil.exe /remove-device" in scripts[0]
        assert "$id -like 'SWD\\WINTUN*'" in scripts[0]
        assert "$_.Present" in scripts[0]
        assert "'PerchVPN'" in scripts[0]
        assert "FriendlyName -like" not in scripts[0]

    def test_live_foreign_wintun_node_is_never_eligible(self, monkeypatch):
        # A live Wintun adapter (for example PattN's singbox_tun) can report
        # PnP Present=False / Status Unknown while its adapter is Up, and
        # every Wintun node shares the FriendlyName 'sing-tun Tunnel'.  The
        # only sound guard is the live adapter PnPDeviceID list.
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        scripts = []

        def run_ps(script):
            scripts.append(script)
            return json.dumps({"removed": [], "remaining": 0})

        tun_helper.cleanup_stale_wintun_adapters("PerchVPN", run_ps=run_ps)
        script = scripts[0]
        assert "Get-NetAdapter" in script
        assert "PnPDeviceID" in script
        assert "if ($live -contains $id) { return $false }" in script
        assert "$_.Status -eq 'Unknown'" not in script

    def test_surviving_nodes_are_reported_not_fatal(self, monkeypatch):
        # pnputil /remove-device needs elevation: a non-elevated caller (or
        # an unremovable phantom) must not abort TUN start — the real
        # CreateAdapter collision, if any, surfaces with its own error.
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        result = tun_helper.cleanup_stale_wintun_adapters(
            "PerchVPN",
            run_ps=lambda script: json.dumps({"removed": [], "remaining": 2}),
        )
        assert result == {"removed": [], "remaining": 2}

    def test_native_fast_path_skips_powershell_when_clean(self, monkeypatch):
        # The clean case used to spend 5-6 s in Get-PnpDevice -Class Net on
        # the sandbox guest.  With the native registry scan there must be no
        # PowerShell and no pnputil when nothing is stale.
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        monkeypatch.setattr(tun_helper, "_native_stale_wintun_devices", lambda: [])
        monkeypatch.setattr(
            tun_helper,
            "_run_ps_write",
            lambda script: pytest.fail("PowerShell must not run for a clean start"),
        )
        monkeypatch.setattr(
            tun_helper.subprocess,
            "run",
            lambda *a, **k: pytest.fail("pnputil must not run for a clean start"),
        )
        result = tun_helper.cleanup_stale_wintun_adapters("PerchVPN")
        assert result == {"removed": [], "remaining": 0}

    def test_native_fast_path_removes_ghosts(self, monkeypatch):
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        scans = iter([
            ["SWD\\WINTUN\\{AAAA}"],
            [],
        ])
        monkeypatch.setattr(
            tun_helper, "_native_stale_wintun_devices", lambda: next(scans)
        )
        calls = []

        class _Done:
            returncode = 0

        monkeypatch.setattr(
            tun_helper.subprocess,
            "run",
            lambda cmd, **kwargs: calls.append(cmd) or _Done(),
        )
        result = tun_helper.cleanup_stale_wintun_adapters("PerchVPN")
        assert result == {"removed": ["SWD\\WINTUN\\{AAAA}"], "remaining": 0}
        assert calls == [["pnputil.exe", "/remove-device", "SWD\\WINTUN\\{AAAA}"]]

    def test_native_scan_unavailable_falls_back_to_powershell(self, monkeypatch):
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        monkeypatch.setattr(tun_helper, "_native_stale_wintun_devices", lambda: None)
        seen = []

        def run_ps(script):
            seen.append(script)
            return json.dumps({"removed": [], "remaining": 1})

        # run_ps=None so the native path is attempted first, then the
        # default runner is exercised through the injected one below.
        monkeypatch.setattr(tun_helper, "_run_ps_write", run_ps)
        result = tun_helper.cleanup_stale_wintun_adapters("PerchVPN")
        assert result == {"removed": [], "remaining": 1}
        assert seen and "pnputil.exe /remove-device" in seen[0]

    def test_invalid_cleanup_output_fails_closed(self, monkeypatch):
        monkeypatch.setattr(tun_helper.sys, "platform", "win32")
        with pytest.raises(RuntimeError, match="invalid JSON"):
            tun_helper.cleanup_stale_wintun_adapters(
                "PerchVPN", run_ps=lambda script: "not-json"
            )


class TestRecoveryOwnership:
    def _adapter_snap(self, guid):
        return _snapshot(adapters=[_adapter("PerchVPN", 41, guid=guid)])

    def test_matching_guid_is_removed(self):
        removed = []

        def remove(name, guid):
            removed.append((name, guid))
            return True

        result = tun_helper.recover_ownership(
            journal={"adapter": "PerchVPN", "adapter_guid": "abc", "child_pid": 0},
            snapshot=self._adapter_snap("abc"),
            remove_adapter=remove,
        )
        assert result["recovered"] is True
        assert removed == [("PerchVPN", "abc")]

    def test_guid_mismatch_is_never_touched(self):
        removed = []
        result = tun_helper.recover_ownership(
            journal={"adapter": "PerchVPN", "adapter_guid": "abc", "child_pid": 0},
            snapshot=self._adapter_snap("different"),
            remove_adapter=lambda n, g: removed.append((n, g)) or True,
        )
        assert result["recovered"] is False
        assert "GUID" in result["detail"]
        assert removed == []

    def test_missing_adapter_counts_as_recovered(self):
        result = tun_helper.recover_ownership(
            journal={"adapter": "PerchVPN", "adapter_guid": "abc", "child_pid": 0},
            snapshot=_snapshot(adapters=[_adapter("Ethernet", 7)]),
        )
        assert result["recovered"] is True

    def test_empty_journal_is_a_noop_success(self):
        result = tun_helper.recover_ownership(journal={})
        assert result["recovered"] is True
        assert "no ownership journal" in result["detail"]


# ---------------------------------------------------------------------------
# P0: never trust the launch, prove the resulting state
# ---------------------------------------------------------------------------


class TestRunHelperP0:
    def test_intent_is_journaled_before_mutation(self, tmp_path, monkeypatch):
        seen = {}

        def boom(cmd):
            seen["journal"] = json.loads((tmp_path / "journal.json").read_text())
            raise OSError("CreateProcess failed")

        final, proc, spawned, commands, _ = TestRunHelper()._run(
            tmp_path, monkeypatch, probe=lambda a: _evidence(), spawn=boom
        )
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "spawn failed" in final["error"]
        assert seen["journal"]["phase"] == "starting"
        assert not (tmp_path / "journal.json").exists()

    def test_bypass_update_pins_and_acknowledges(self, tmp_path, monkeypatch):
        bypass = tmp_path / "bypass.json"
        bypass.write_text(json.dumps({"version": 1, "ips": ["203.0.113.77"]}))
        alive = {"n": 0}

        def parent_alive(pid):
            alive["n"] += 1
            return alive["n"] <= 6

        host = FakeHostRoutes()
        final, proc, spawned, commands, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            host=host,
            bypass_path=bypass,
            parent_alive=parent_alive,
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        assert final["bypass_version"] == 1
        assert final["bypass_error"] == ""
        cfg = json.loads(Path(spawned[0][-1]).read_text(encoding="utf-8"))
        assert "203.0.113.77/32" in cfg["inbounds"][0]["route_exclude_address"]


class TestClientBypassAck:
    def _client(self, tmp_path, state_path, sleep):
        return tun_helper.TunHelperClient(
            spec=_spec(),
            state_path=state_path,
            stop_path=tmp_path / "stop",
            spec_path=tmp_path / "spec.json",
            sleep=sleep,
            clock=FakeClock(),
        )

    def test_update_waits_for_matching_version(self, tmp_path):
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps({"phase": "ready", "bypass_version": 0}))

        class Ack:
            def __init__(self):
                self.calls = 0

            async def sleep(self, seconds):
                self.calls += 1
                payload = json.loads(
                    (tmp_path / "tun-helper-bypass.json").read_text()
                )
                state_path.write_text(
                    json.dumps(
                        {
                            "phase": "ready",
                            "bypass_version": payload["version"],
                            "bypass_error": "",
                        }
                    )
                )

        client = self._client(tmp_path, state_path, Ack().sleep)
        state = asyncio.run(client.update_bypass(["203.0.113.9"], timeout=5.0))
        assert state["bypass_version"] == 1

    def test_refused_update_raises(self, tmp_path):
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps({"phase": "ready", "bypass_version": 0}))

        class Refuse:
            async def sleep(self, seconds):
                payload = json.loads(
                    (tmp_path / "tun-helper-bypass.json").read_text()
                )
                state_path.write_text(
                    json.dumps(
                        {
                            "phase": "ready",
                            "bypass_version": payload["version"],
                            "bypass_error": "route_preempted: 203.0.113.9",
                        }
                    )
                )

        client = self._client(tmp_path, state_path, Refuse().sleep)
        with pytest.raises(tun_helper.CoexistenceError):
            asyncio.run(client.update_bypass(["203.0.113.9"], timeout=5.0))


class TestActivationSafety:
    def test_ipv6_bypass_is_never_pinned_as_a_fake_v4_slash32(self, tmp_path, monkeypatch):
        final, proc, spawned, commands, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            spec=_spec(bypass=["2001:db8::1", "203.0.113.9"]),
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED
        cfg = json.loads(Path(spawned[0][-1]).read_text(encoding="utf-8"))
        assert "2001:db8::1/128" in cfg["inbounds"][0]["route_exclude_address"]
        assert "203.0.113.9/32" in cfg["inbounds"][0]["route_exclude_address"]

    def test_unexpected_sidecar_exit_is_reported_as_failure(self, tmp_path, monkeypatch):
        proc = FakeProcess()

        def parent_alive(pid):
            proc.returncode = 1
            return True

        final, unused, spawned, commands, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=lambda a: _evidence(),
            parent_alive=parent_alive,
            spawn=lambda cmd: proc,
        )
        # The loop may already have exited on the injected death; either the
        # "exited before" or the "exited unexpectedly" failure is honest.
        assert final["phase"] == tun_helper.PHASE_FAILED
        assert "exited" in final["error"]
        assert final.get("stop_reason") == "sidecar-exited"
        assert final.get("sidecar_exit_code") == 1
        assert not (tmp_path / "journal.json").exists()

    def test_foreign_route_churn_is_not_our_residual(self, tmp_path, monkeypatch):
        """The underlay hot-swaps its own routes; that is not teardown damage."""
        from perchvpn_windows.tun_state_capture import StateDifference

        async def probe(adapter):
            return _evidence()

        foreign = StateDifference(
            category="route",
            description="Route removed: ('ff00::/8', '::', 56, 'ActiveStore')",
            baseline_value={
                "DestinationPrefix": "ff00::/8",
                "NextHop": "::",
                "InterfaceIndex": 56,
                "PolicyStore": "ActiveStore",
            },
            current_value=None,
        )
        final, _, _, _, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            compare=lambda a, b: [foreign],
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final.get("residual")
        assert not final.get("residual")

    def test_foreign_adapter_churn_is_not_our_residual(self, tmp_path, monkeypatch):
        """A second VPN creating its adapter/interface during our run is not ours."""
        from perchvpn_windows.tun_state_capture import StateDifference

        async def probe(adapter):
            return _evidence()

        foreign = [
            StateDifference(
                category="adapter",
                description="Adapter added: singbox_tun",
                current_value=_adapter("singbox_tun", 56, guid="guid-foreign"),
            ),
            StateDifference(
                category="ip_address",
                description="IP added: (56, '172.18.0.1', 2)",
                current_value=_ip(56, "172.18.0.1"),
            ),
            StateDifference(
                category="dns",
                description="DNS added for interface 23",
                current_value={
                    "InterfaceIndex": 23,
                    "AddressFamily": 23,
                    "ServerAddresses": [],
                },
            ),
            StateDifference(
                category="interface",
                description="Interface 2 added",
                current_value=_iface(2, metric=5000),
            ),
        ]
        final, _, _, _, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            compare=lambda a, b: list(foreign),
        )
        assert final["phase"] == tun_helper.PHASE_STOPPED, final.get("residual")
        assert not final.get("residual")

    def test_residual_dns_on_our_adapter_is_still_reported(self, tmp_path, monkeypatch):
        from perchvpn_windows.tun_state_capture import StateDifference

        async def probe(adapter):
            return _evidence()

        leftover = StateDifference(
            category="dns",
            description="DNS changed for interface 41",
            baseline_value={
                "InterfaceIndex": 41,
                "AddressFamily": 2,
                "ServerAddresses": ["10.7.0.2"],
            },
            current_value={
                "InterfaceIndex": 41,
                "AddressFamily": 2,
                "ServerAddresses": ["1.1.1.1"],
            },
        )
        final, _, _, _, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            compare=lambda a, b: [leftover],
        )
        assert final["phase"] == tun_helper.PHASE_RECOVERY
        assert final["residual"] == ["dns: " + leftover.description]

    def test_residual_on_our_adapter_is_still_reported(self, tmp_path, monkeypatch):
        from perchvpn_windows.tun_state_capture import StateDifference

        async def probe(adapter):
            return _evidence()

        leftover = StateDifference(
            category="route",
            description="Route removed: ('0.0.0.0/1', '0.0.0.0', 41, 'ActiveStore')",
            baseline_value={
                "DestinationPrefix": "0.0.0.0/1",
                "NextHop": "0.0.0.0",
                "InterfaceIndex": 41,
                "PolicyStore": "ActiveStore",
            },
            current_value=None,
        )
        final, _, _, _, _ = TestRunHelper()._run(
            tmp_path,
            monkeypatch,
            probe=probe,
            compare=lambda a, b: [leftover],
        )
        assert final["phase"] == tun_helper.PHASE_RECOVERY
        assert final["residual"] == ["route: " + leftover.description]


class TestPhysicalSelection:
    def test_gateway_comes_from_the_physical_lan_route(self):
        snap = _snapshot(
            routes=[_default_route(56, next_hop="172.18.0.2"), _default_route(7)],
            adapters=[
                _adapter("Ethernet", 7),
                _adapter("singbox_tun", 56, guid="guid-singbox"),
            ],
            ip_addresses=[_ip(7, "198.51.100.5")],
        )
        index, gateway = tun_helper.physical_route_gateway(snap, "198.51.100.5")
        assert index == 7
        assert gateway == "192.168.1.1"

    def test_unknown_egress_has_no_carrier(self):
        snap = _snapshot(
            routes=[_default_route(7)],
            adapters=[_adapter("Ethernet", 7)],
            ip_addresses=[_ip(7, "198.51.100.5")],
        )
        assert tun_helper.physical_route_gateway(snap, "203.0.113.77") == (None, "")

    def test_route_lookup_is_excised_under_native_singbox(self):
        # Native sing-box owns interface routing (auto_route) and excludes
        # upstream destinations via route_exclude_address, so the legacy
        # NextHop/route-interface probing is stubbed out: lookups never
        # select an adapter, and missing DNS/gateway enumeration is not a
        # precondition anywhere.
        assert tun_helper.find_route_interface("192.168.1.1") is None
        assert tun_helper.find_route_interface("8.8.8.8") is None
        assert tun_helper.find_route_interface("203.0.113.9") is None

    def test_virtual_adapters_are_recognised(self):
        for name in ("singbox_tun", "Tailscale", "vEthernet (Default Switch)",
                     "tun2proxy", "PerchVPN"):
            assert tun_helper._is_virtual_adapter(_adapter(name, 9)), name

    def test_real_adapters_are_accepted(self):
        for name in ("Wi-Fi", "Ethernet", "Realtek 8821CE Wireless LAN 802.11ac"):
            record = _adapter(name, 10)
            record["InterfaceDescription"] = name
            assert not tun_helper._is_virtual_adapter(record), name


class TestEstablishedEndpointProtection:
    def test_public_ipv4_endpoints_only(self):
        table = "\n".join(
            [
                "104.18.32.7",
                "10.0.0.5",
                "192.168.1.9",
                "127.0.0.1",
                "fe80::1",
                "2606:4700::1111",
                "104.18.32.7",
                "",
            ]
        )
        assert tun_helper.established_remote_endpoints(run_ps=lambda s: table) == [
            "104.18.32.7"
        ]

    def test_unreadable_table_is_best_effort(self):
        def boom(script):
            raise tun_helper.PowerShellError("denied")

        assert tun_helper.established_remote_endpoints(run_ps=boom) == []


class TestRecoverCli:
    def test_recover_reads_the_journal_dict_and_returns_success(
        self, tmp_path, monkeypatch
    ):
        from perchvpn_windows import cli

        journal_path = tmp_path / "journal.json"
        journal_path.write_text("{}")
        seen = {}

        def fake_recover(*, journal, **kwargs):
            seen["journal"] = journal
            return {"recovered": True}

        monkeypatch.setattr(
            tun_helper, "load_journal", lambda path: {"adapter": "PerchVPN"}
        )
        monkeypatch.setattr(tun_helper, "recover_ownership", fake_recover)

        assert cli.main(["--tun-helper-recover", str(journal_path)]) == 0
        assert seen["journal"] == {"adapter": "PerchVPN"}

    def test_recover_without_argument_is_a_noop_success(self, monkeypatch):
        from perchvpn_windows import cli

        called = []
        monkeypatch.setattr(
            tun_helper, "load_journal", lambda path: called.append(path) or {}
        )
        assert cli.main(["--tun-helper-recover"]) == 0
        assert called == []
