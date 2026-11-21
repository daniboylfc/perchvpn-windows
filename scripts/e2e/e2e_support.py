"""Pure helpers for the PerchVPN client E2E harness.

Kept side-effect free so they can be unit-tested on the WSL side while the
harness itself only runs inside the Windows guest.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Sequence


def split_route_evidence(
    defaults: Sequence[Any], tun_routes: Sequence[Any], adapter: str
) -> Dict[str, Any]:
    """Prove the tunnel owns both halves of the IPv4 default space.

    sing-box 1.14 with ``auto_route`` + ``route_exclude_address`` does not
    install the literal ``0.0.0.0/1`` + ``128.0.0.0/1`` pair; it decomposes
    the halves into a long list of exclusion-aware prefixes pointing at the
    TUN gateway.  Literal prefixes still satisfy the check when present;
    otherwise the decomposed set must carry public probe addresses from both
    halves through the TUN interface via a gateway next hop.
    """
    probes = {
        "0.0.0.0/1": ("1.0.0.1", "8.8.8.8", "64.0.0.1"),
        "128.0.0.0/1": ("129.0.0.1", "200.0.0.1", "208.0.0.1"),
    }
    literal = [
        r
        for r in defaults
        if r.get("InterfaceAlias") == adapter
        and r.get("DestinationPrefix") in ("0.0.0.0/1", "128.0.0.0/1")
    ]
    halves = {half: False for half in probes}
    decomposed: List[str] = []
    for route in tun_routes:
        if route.get("InterfaceAlias") != adapter:
            continue
        next_hop = str(route.get("NextHop") or "")
        if next_hop in ("", "0.0.0.0", "::"):
            continue
        prefix = str(route.get("DestinationPrefix") or "")
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        covers_probe = False
        for half, addresses in probes.items():
            for ip in addresses:
                if ipaddress.ip_address(ip) in network:
                    covers_probe = True
                    if not halves[half]:
                        halves[half] = True
                    break
        if covers_probe:
            decomposed.append(prefix)
    decomposed_covered = all(halves.values())
    return {
        "ok": len(literal) == 2 or decomposed_covered,
        "literal": literal,
        "decomposed_count": len(decomposed),
        "decomposed_sample": decomposed[:8],
        "halves_covered": halves,
        "via": "literal" if len(literal) == 2 else (
            "decomposed" if decomposed_covered else "missing"
        ),
    }
