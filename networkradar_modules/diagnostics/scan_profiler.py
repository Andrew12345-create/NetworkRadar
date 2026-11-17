"""Per-scan phase timing for NetworkRadar.

The profiler is deliberately in-memory and bounded: it records durations and
error types, never packet contents, credentials, hostnames, or raw exceptions.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import threading
import time
from typing import Iterator


class ScanProfiler:
    """Thread-safe accumulator for named scan phases."""

    def __init__(self, scan_number: int, network: str = "") -> None:
        self.scan_number = max(0, int(scan_number))
        self.network = str(network or "")[:64]
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._clock_started = time.monotonic()
        self._lock = threading.RLock()
        self._phases: dict[str, dict] = {}

    @contextmanager
    def measure(self, name: str) -> Iterator[None]:
        """Measure a phase; repeated names accumulate and exceptions propagate."""
        phase_name = str(name or "unnamed")[:96]
        started = time.monotonic()
        error_type = ""
        try:
            yield
        except Exception as exc:
            error_type = type(exc).__name__[:80]
            raise
        finally:
            elapsed = max(0.0, time.monotonic() - started)
            with self._lock:
                item = self._phases.setdefault(phase_name, {
                    "calls": 0,
                    "duration_seconds": 0.0,
                    "last_duration_seconds": 0.0,
                    "max_duration_seconds": 0.0,
                    "errors": 0,
                    "last_error_type": "",
                })
                item["calls"] += 1
                item["duration_seconds"] += elapsed
                item["last_duration_seconds"] = elapsed
                item["max_duration_seconds"] = max(item["max_duration_seconds"], elapsed)
                if error_type:
                    item["errors"] += 1
                    item["last_error_type"] = error_type

    def snapshot(self) -> dict:
        """Return a JSON-safe snapshot ordered by cumulative duration."""
        with self._lock:
            phases = [
                {
                    **item,
                    "duration_seconds": round(item["duration_seconds"], 3),
                    "last_duration_seconds": round(item["last_duration_seconds"], 3),
                    "max_duration_seconds": round(item["max_duration_seconds"], 3),
                }
                for name, item in self._phases.items()
                for item in [dict(item, name=name)]
            ]
        phases.sort(key=lambda item: item["duration_seconds"], reverse=True)
        elapsed = max(0.0, time.monotonic() - self._clock_started)
        return {
            "available": True,
            "schema_version": 1,
            "scan_number": self.scan_number,
            "network": self.network,
            "started_at": self.started_at,
            "total_duration_seconds": round(elapsed, 3),
            "phase_count": len(phases),
            "slowest_phase": phases[0]["name"] if phases else "",
            "phases": phases[:40],
        }


def measure_phase(profiler: ScanProfiler | None, name: str):
    """Return a profiler context or a no-op context for optional instrumentation."""
    return profiler.measure(name) if profiler is not None else nullcontext()
