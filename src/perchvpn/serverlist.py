"""VPN server list discovery via Firefox Remote Settings."""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .headers import apply_mozilla_vpn_headers
from .http_client import get_client

logger = logging.getLogger("perchvpn.serverlist")

REMOTE_SETTINGS_URL = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
)

# Remote Settings carries a synthetic "CatchAll Anycast" entry that is not a
# real country a user can select. The Android client excludes it by name
# (ServerListClient.EXCLUDED_COUNTRY_NAMES); match that case-insensitively so
# it never appears in country selection.
EXCLUDED_COUNTRY_NAMES = frozenset({"catchall anycast"})


@dataclass
class Protocol:
    name: str
    host: str = ""
    port: int = 0
    scheme: str = ""
    template_string: str = ""

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Protocol":
        return cls(
            name=data.get("name", ""),
            host=data.get("host", ""),
            port=int(data.get("port", 0) or 0),
            scheme=data.get("scheme", ""),
            template_string=data.get("templateString", ""),
        )


@dataclass
class Server:
    hostname: str
    port: int = 0
    quarantined: bool = False
    protocols: List[Protocol] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Server":
        return cls(
            hostname=data.get("hostname", ""),
            port=int(data.get("port", 0) or 0),
            quarantined=bool(data.get("quarantined", False)),
            protocols=[Protocol.from_json(p) for p in data.get("protocols", [])],
        )


@dataclass
class City:
    name: str
    code: str
    servers: List[Server] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "City":
        return cls(
            name=data.get("name", ""),
            code=data.get("code", ""),
            servers=[Server.from_json(s) for s in data.get("servers", [])],
        )


@dataclass
class Country:
    name: str
    code: str
    cities: List[City] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Country":
        return cls(
            name=data.get("name", ""),
            code=data.get("code", ""),
            cities=[City.from_json(c) for c in data.get("cities", [])],
        )


def _parse_server_list(body: Dict[str, Any]) -> List[Country]:
    records = body.get("data", []) or []
    countries: List[Country] = []
    for record in records:
        country_data = record.get("country", record)
        try:
            country = Country.from_json(country_data)
        except Exception:  # noqa: BLE001
            continue
        # Mirrors the original Go client: skip malformed/placeholder records
        # that have no country code or no cities, instead of surfacing them
        # as blank entries in --list-servers output or to country-selection
        # logic. The synthetic "CatchAll Anycast" entry is also excluded by
        # name, matching the Android client.
        if country.code and country.cities and country.name.strip().lower() not in EXCLUDED_COUNTRY_NAMES:
            countries.append(country)
    return countries


def _cache_path(cache_path: Optional[Union[str, Path]]) -> Optional[Path]:
    return Path(cache_path) if cache_path else None


def _save_cache(cache_path: Optional[Union[str, Path]], raw: str) -> None:
    """Persist the raw Remote Settings payload atomically (temp file +
    os.replace), mirroring the Android client's ServerListClient cache."""
    path = _cache_path(cache_path)
    if path is None or not raw:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(raw)
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
    except OSError as exc:
        logger.warning("could not write the server list cache: %s", exc)


def load_cached_server_list(cache_path: Optional[Union[str, Path]]) -> List[Country]:
    """Parse a previously cached Remote Settings payload; returns an empty
    list when there is no usable cache (missing, unreadable, or malformed)."""
    path = _cache_path(cache_path)
    if path is None:
        return []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        return _parse_server_list(json.loads(raw))
    except Exception as exc:  # noqa: BLE001
        # Valid JSON can still be the wrong shape (e.g. [], a scalar, or
        # {"data": {}}); treat any such cache as unusable so a corrupt file
        # never masks the original fetch error.
        logger.warning("ignoring unreadable server list cache: %s", exc)
        return []


def _fresh_cached_server_list(
    cache_path: Union[str, Path], max_age: float
) -> List[Country]:
    """Cached countries when the cache file is younger than ``max_age``."""
    path = _cache_path(cache_path)
    if path is None or max_age <= 0:
        return []
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return []
    if age > max_age:
        return []
    return load_cached_server_list(path)


def fetch_server_list(    cache_path: Optional[Union[str, Path]] = None,
    *,
    max_cache_age: Optional[float] = None,
) -> List[Country]:
    """Fetch the server list from Remote Settings.

    When ``cache_path`` is given, a successful non-empty result is cached
    (atomically) and a network/parse failure transparently falls back to that
    cache, so a transient control-plane outage does not prevent startup.
    Without a ``cache_path`` the behaviour is unchanged: failures propagate.

    ``max_cache_age`` (seconds) makes a *fresh* cache authoritative: Connect
    runs right after the GUI's own server-list fetch, and paying a second
    control-plane round trip there is pure click latency.  Staleness is
    bounded by the caller (country lists change rarely); a stale or missing
    cache still takes the network path.
    """
    if max_cache_age is not None and cache_path is not None:
        cached = _fresh_cached_server_list(cache_path, max_cache_age)
        if cached:
            return cached
    client = get_client()
    try:
        response = client.get(REMOTE_SETTINGS_URL, headers=apply_mozilla_vpn_headers({}))
        response.raise_for_status()
        raw = response.text
        countries = _parse_server_list(response.json())
    except Exception as exc:  # noqa: BLE001
        cached = load_cached_server_list(cache_path)
        if cached:
            logger.warning(
                "server list fetch failed (%s); using %d cached country/countries",
                exc,
                len(cached),
            )
            return cached
        raise
    if countries and cache_path is not None:
        _save_cache(cache_path, raw)
    return countries


def print_server_list(countries: List[Country]) -> None:
    for country in countries:
        print(f"\n=== {country.name} ({country.code}) ===")
        for city in country.cities:
            print(f"  City: {city.name} ({city.code})")
            for server in city.servers:
                if server.quarantined:
                    print(f"    [QUARANTINED] {server.hostname}:{server.port}")
                    continue
                print(f"    Server: {server.hostname}:{server.port}")
                for proto in server.protocols:
                    if proto.name == "connect":
                        scheme = proto.scheme or "https"
                        print(f"      Protocol: CONNECT ({scheme}) -> {proto.host}:{proto.port}")
                    elif proto.name == "masque":
                        print(
                            f"      Protocol: MASQUE -> {proto.host}:{proto.port} "
                            f"(template: {proto.template_string})"
                        )
                    else:
                        print(f"      Protocol: {proto.name} -> {proto.host}:{proto.port}")
                if not server.protocols:
                    print(f"      Protocol: CONNECT (https) -> {server.hostname}:{server.port} (default)")
