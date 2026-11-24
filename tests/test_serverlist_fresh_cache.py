"""Connect reuses a server list the GUI just fetched.

Connect used to pay a second Remote Settings round trip even when the cache
file had been written moments earlier by the GUI's own /api/countries call.
"""

from __future__ import annotations

import os
import time

import pytest

from src.perchvpn import serverlist

SAMPLE = {
    "data": [
        {
            "name": "Testland",
            "code": "tl",
            "cities": [
                {
                    "name": "Test City",
                    "code": "tst",
                    "servers": [
                        {
                            "hostname": "relay.example.net",
                            "port": 443,
                            "quarantined": False,
                            "protocols": [
                                {"name": "connect", "host": "edge.example.net", "port": 443}
                            ],
                        }
                    ],
                }
            ],
        }
    ]
}


@pytest.fixture
def cache_path(tmp_path):
    path = tmp_path / "serverlist.json"
    path.write_text(serverlist.json.dumps(SAMPLE), encoding="utf-8")
    return path


def test_fresh_cache_is_authoritative(cache_path, monkeypatch):
    calls = []

    def boom(*args, **kwargs):
        calls.append(args)
        raise AssertionError("the network must not be touched for a fresh cache")

    monkeypatch.setattr(serverlist, "get_client", boom)
    countries = serverlist.fetch_server_list(cache_path, max_cache_age=120.0)
    assert [c.code for c in countries] == ["tl"]
    assert calls == []


def test_stale_cache_falls_back_to_the_network(cache_path, monkeypatch):
    old = time.time() - 600
    os.utime(cache_path, (old, old))

    class Response:
        text = serverlist.json.dumps(SAMPLE)
        json = staticmethod(lambda: SAMPLE)

        def raise_for_status(self):
            return None

    class Client:
        def get(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(serverlist, "get_client", lambda: Client())
    countries = serverlist.fetch_server_list(cache_path, max_cache_age=120.0)
    assert [c.code for c in countries] == ["tl"]


def test_without_max_age_the_network_is_always_used(cache_path, monkeypatch):
    calls = []

    class Response:
        text = serverlist.json.dumps(SAMPLE)
        json = staticmethod(lambda: SAMPLE)

        def raise_for_status(self):
            return None

    class Client:
        def get(self, *args, **kwargs):
            calls.append(1)
            return Response()

    monkeypatch.setattr(serverlist, "get_client", lambda: Client())
    serverlist.fetch_server_list(cache_path)
    assert calls == [1]
