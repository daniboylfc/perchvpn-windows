"""Focused tests for Guardian 406/Fastly-challenge retry handling.

Matches upstream v1.0.7 semantics: a 406 triggers a challenge solve and one
retry, repeated at most GUARDIAN_MAX_CHALLENGE_ATTEMPTS times before the last
response is returned to the caller.
"""

from __future__ import annotations

import threading

import pytest

import perchvpn.guardian as guardian
from perchvpn.exceptions import FastlyChallengeError


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeClient:
    def __init__(self, status_code_one_shot=200, always=None):
        self.requests: list[str] = []
        self.lock = threading.Lock()
        self._always = always
        self.status_code_one_shot = status_code_one_shot

    def request(self, method, url, headers=None, **kwargs):  # noqa: ANN001, ANN003
        with self.lock:
            self.requests.append(f"{method} {url}")
            if self._always is not None:
                return _FakeResponse(self._always)
            code, self.status_code_one_shot = self.status_code_one_shot, 200
            return _FakeResponse(code)


@pytest.fixture()
def patched(monkeypatch):
    solves: list[str] = []

    def solve(client, response):  # noqa: ANN001
        solves.append(response.status_code)

    monkeypatch.setattr(guardian, "solve_fastly_challenge", solve)
    return solves


def test_initial_success_makes_one_request_without_challenge(patched, monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(guardian, "get_client", lambda: client)

    response = guardian._authorized_request("GET", "https://vpn.example/api", "tok")

    assert response.status_code == 200
    assert client.requests == ["GET https://vpn.example/api"]
    assert patched == []


def test_challenge_then_success_solves_once_and_retries(patched, monkeypatch):
    client = _FakeClient(status_code_one_shot=406)
    monkeypatch.setattr(guardian, "get_client", lambda: client)

    response = guardian._authorized_request("GET", "https://vpn.example/api", "tok")

    assert response.status_code == 200
    assert client.requests == ["GET https://vpn.example/api"] * 2
    assert patched == [406]


def test_persistent_406_capped_at_five_retries(patched, monkeypatch):
    client = _FakeClient(always=406)
    monkeypatch.setattr(guardian, "get_client", lambda: client)

    response = guardian._authorized_request("GET", "https://vpn.example/api", "tok")

    assert response.status_code == 406
    assert len(client.requests) == 1 + guardian.GUARDIAN_MAX_CHALLENGE_ATTEMPTS
    assert len(patched) == guardian.GUARDIAN_MAX_CHALLENGE_ATTEMPTS


def test_challenge_error_propagates_and_stops_retrying(patched, monkeypatch):
    client = _FakeClient(always=406)
    monkeypatch.setattr(guardian, "get_client", lambda: client)

    def failing_solve(client, response):  # noqa: ANN001
        raise FastlyChallengeError("no candidate host served a challenge")

    monkeypatch.setattr(guardian, "solve_fastly_challenge", failing_solve)

    with pytest.raises(FastlyChallengeError):
        guardian._authorized_request("GET", "https://vpn.example/api", "tok")

    assert len(client.requests) == 1
