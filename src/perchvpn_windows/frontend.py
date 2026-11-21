"""Windows SOCKS5 frontend: thin lifecycle wrapper around the owned core Socks5Server."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from perchvpn.proxy.pool import SessionPool
from perchvpn.proxy.socks import Socks5Server
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from perchvpn_windows.metrics import TrafficMetrics

logger = logging.getLogger("perchvpn_windows.frontend")


class Socks5Frontend:
    """Windows-facing SOCKS5 frontend using the owned Perch VPN Socks5Server."""

    def __init__(
        self,
        pool: Optional[SessionPool],
        host: str,
        port: int,
        max_connections: int = 256,
        idle_timeout: float = 0.0,
        metrics: Optional["TrafficMetrics"] = None,
        upstream_proxy: Optional["".join(["perchvpn_windows.config", ".UpstreamProxyConfig"])] = None,
        proxy_only_mode: bool = False,
        local_proxy_users: Optional[dict] = None,
    ):
        self._host = host
        self._port = port
        self._server = Socks5Server(
            host=host,
            port=port,
            pool=pool,
            max_connections=max_connections,
            idle_timeout=idle_timeout,
            metrics=metrics,
            upstream_proxy=upstream_proxy,
            proxy_only_mode=proxy_only_mode,
            local_proxy_users=local_proxy_users,
        )
        self._serve_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the SOCKS5 server listener."""
        logger.info("starting SOCKS5 proxy on %s:%s", self._host, self._port)
        try:
            await self._server.start()
        except Exception as exc:
            winerror = getattr(exc, "winerror", None)
            hint = ""
            if winerror == 10048:
                hint = (
                    " (port already in use; another PerchVPN instance or "
                    "process owns the port)"
                )
            logger.error(
                "SOCKS5 proxy failed to bind %s:%s: %s: %s%s",
                self._host,
                self._port,
                type(exc).__name__,
                exc,
                hint,
            )
            raise
        if self._server.proxy_only_mode:
            logger.info("SOCKS5 proxy listening on %s:%s (proxy-only mode)", self._host, self._port)
        else:
            logger.info("SOCKS5 proxy listening on %s:%s", self._host, self._port)

    async def serve_forever(self) -> None:
        """Run the server until stopped."""
        await self._server.serve_forever()

    async def stop(self) -> None:
        """Stop the SOCKS5 server."""
        await self._server.close()
        logger.info("SOCKS5 proxy stopped")

    def set_pool(self, pool: Optional[SessionPool],
                 metrics: Optional["TrafficMetrics"] = None) -> None:
        """Hot-swap the upstream pool without restarting the listener."""
        self._server.set_pool(pool, metrics)

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port
