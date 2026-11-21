"""The shared control-plane client must survive rebuilds while a request
started on the previous client is still in flight.

Root cause of httpx's "Cannot send a request, as the client has been closed."
during initialization: the client mutators (set_local_address / timeout /
proxy / DoH) used to ``close()`` the shared client while another thread was
mid-request on it, and the startup preflight worker could rebuild the client
at any later moment (asyncio.to_thread is uncancellable after its timeout).
"""

from __future__ import annotations

import threading
import time

import httpx
import pytest

from perchvpn import http_client


@pytest.fixture(autouse=True)
def _isolate_shared_client(monkeypatch):
    saved = (
        http_client._client,
        http_client._proxy_url,
        http_client._timeout,
        http_client._local_address,
        http_client._physical_interface,
    )
    http_client._client = None
    http_client._proxy_url = None
    yield
    (
        http_client._client,
        http_client._proxy_url,
        http_client._timeout,
        http_client._local_address,
        http_client._physical_interface,
    ) = saved


def _patch_mock_build(monkeypatch, handler):
    def fake_build(use_doh: bool = False) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(http_client, "_build_client", fake_build)


def test_rebuild_does_not_kill_in_flight_request(monkeypatch):
    handler_calls = []

    def slow_handler(request: httpx.Request) -> httpx.Response:
        handler_calls.append(request.url.path)
        time.sleep(0.3)
        return httpx.Response(200, text="ok")

    _patch_mock_build(monkeypatch, slow_handler)
    first = http_client.get_client()
    result: dict[str, object] = {}

    def request_in_flight():
        try:
            response = first.get("https://control.example/api/status")
            result["status"] = response.status_code
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    worker = threading.Thread(target=request_in_flight)
    worker.start()
    time.sleep(0.05)  # let the request enter the transport
    # A concurrent mutator rebuilds the shared client mid-flight.
    http_client.set_control_plane_timeout(9.0)
    worker.join(timeout=5)

    assert "error" not in result, result
    assert result["status"] == 200
    assert handler_calls == ["/api/status"]
    # The shared handle now points at a fresh client with the new timeout.
    rebuilt = http_client.get_client()
    assert rebuilt is not first


def test_rebuild_twice_keeps_each_in_flight_request_alive(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        time.sleep(0.25)
        return httpx.Response(200, text=request.url.path)

    _patch_mock_build(monkeypatch, handler)
    errors: list[Exception] = []

    def worker(path: str):
        try:
            response = http_client.get_client().get("https://control.example" + path)
            assert response.text == path
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(path,)) for path in ("/a", "/b", "/c")]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    http_client.set_control_plane_timeout(8.0)
    time.sleep(0.05)
    http_client.set_control_plane_proxy(None)
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
