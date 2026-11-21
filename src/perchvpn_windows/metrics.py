"""Runtime traffic and connection metrics for the Windows frontend."""

import time
from dataclasses import dataclass, field


@dataclass
class TrafficMetrics:
    """Lightweight runtime traffic counters."""

    started_at: float = field(default_factory=time.monotonic)
    uploaded: int = 0
    downloaded: int = 0
    active_connections: int = 0

    _last_sample: float = field(default_factory=time.monotonic, init=False, repr=False)
    _last_uploaded: int = field(default=0, init=False, repr=False)
    _last_downloaded: int = field(default=0, init=False, repr=False)
    _upload_speed: float = field(default=0.0, init=False, repr=False)
    _download_speed: float = field(default=0.0, init=False, repr=False)

    def add_uploaded(self, amount: int) -> None:
        self.uploaded += amount
        self._sample()

    def add_downloaded(self, amount: int) -> None:
        self.downloaded += amount
        self._sample()

    def connection_opened(self) -> None:
        self.active_connections += 1

    def connection_closed(self) -> None:
        self.active_connections = max(0, self.active_connections - 1)

    def _sample(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_sample

        if elapsed < 0.25:
            return

        self._upload_speed = (self.uploaded - self._last_uploaded) / elapsed
        self._download_speed = (self.downloaded - self._last_downloaded) / elapsed
        self._last_uploaded = self.uploaded
        self._last_downloaded = self.downloaded
        self._last_sample = now

    @property
    def upload_speed(self) -> float:
        self._sample()
        return self._upload_speed

    @property
    def download_speed(self) -> float:
        self._sample()
        return self._download_speed

    @property
    def total(self) -> int:
        return self.uploaded + self.downloaded

    @property
    def uptime(self) -> float:
        return max(0.0, time.monotonic() - self.started_at)
