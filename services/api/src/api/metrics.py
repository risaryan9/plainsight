"""Per-scan resource measurement, for sizing the worker later."""

from __future__ import annotations

import os
import threading
import time
from types import TracebackType
from typing import Self

_SAMPLE_INTERVAL_S = 0.1


def current_rss_bytes() -> int | None:
    """Resident memory of this process right now. None where /proc is unavailable."""
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            resident_pages = int(fh.read().split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return resident_pages * os.sysconf("SC_PAGE_SIZE")


class ScanMeter:
    """Context manager that records wall time and the peak resident memory inside it."""

    def __init__(self) -> None:
        self.duration_s = 0.0
        self.start_rss_bytes = current_rss_bytes()
        self.peak_rss_bytes = self.start_rss_bytes
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, name="scan-meter", daemon=True)
        self._started_at = 0.0

    def _sample(self) -> None:
        while not self._stop.wait(_SAMPLE_INTERVAL_S):
            self._record()

    def _record(self) -> None:
        rss = current_rss_bytes()
        if rss is not None and (self.peak_rss_bytes is None or rss > self.peak_rss_bytes):
            self.peak_rss_bytes = rss

    def __enter__(self) -> Self:
        self._started_at = time.perf_counter()
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join()
        self._record()
        self.duration_s = time.perf_counter() - self._started_at

    @property
    def peak_rss_mb(self) -> float | None:
        return None if self.peak_rss_bytes is None else self.peak_rss_bytes / 1_048_576
