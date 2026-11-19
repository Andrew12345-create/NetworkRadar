"""Bounded host-only WAN traffic generator for an operator-controlled HTTPS endpoint.

The engine originates HTTPS downloads from this host only. It never installs
agents on LAN clients, targets arbitrary destinations, or changes router rules.
The endpoint must be owned by, or explicitly authorised for use by, the operator.

Rate limiting is applied before each socket read so TCP receive-window back
pressure can regulate the actual download rather than merely delaying data
after it has already crossed the WAN.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_DURATION_SECONDS = 180
MAX_AGGREGATE_MBPS = 100
MAX_STREAMS = 8
MIN_TOTAL_MB = 16
MAX_TOTAL_MB = 1024
MAX_TOTAL_BYTES = MAX_TOTAL_MB * 1024 * 1024
CHUNK_SIZE = 64 * 1024
VALID_PROFILES = {"Light", "Moderate", "High", "Extreme", "Custom"}


def validate_test_config(endpoint, duration_seconds=30, aggregate_mbps=5,
                         streams=2, max_total_mb=256, profile="Custom",
                         resolver=None):
    raw = str(endpoint or "").strip()
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Endpoint must be a complete HTTPS URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Endpoint URLs cannot contain credentials or fragments.")
    if parsed.port not in (None, 443):
        raise ValueError("Only standard HTTPS port 443 is supported.")
    if len(raw) > 2048:
        raise ValueError("Endpoint URL is too long.")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or not 5 <= duration_seconds <= MAX_DURATION_SECONDS:
        raise ValueError("Duration must be between 5 and 180 seconds.")
    if isinstance(aggregate_mbps, bool) or not isinstance(aggregate_mbps, (int, float)) or not 0.5 <= float(aggregate_mbps) <= MAX_AGGREGATE_MBPS:
        raise ValueError("Aggregate traffic rate must be between 0.5 and 100 Mbps.")
    if isinstance(streams, bool) or not isinstance(streams, int) or not 1 <= streams <= MAX_STREAMS:
        raise ValueError("Parallel streams must be between 1 and 8.")
    if isinstance(max_total_mb, bool) or not isinstance(max_total_mb, int) or not MIN_TOTAL_MB <= max_total_mb <= MAX_TOTAL_MB:
        raise ValueError("Total data allowance must be between 16 and 1024 MB.")
    if str(profile) not in VALID_PROFILES:
        raise ValueError("Unknown load profile.")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        lookup = resolver or socket.getaddrinfo
        try:
            addresses = sorted({item[4][0] for item in lookup(host, 443, type=socket.SOCK_STREAM)})
        except OSError as exc:
            raise ValueError("Endpoint hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("Endpoint hostname did not resolve to an address.")
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Endpoint resolved to an invalid address.") from exc
        if (not address.is_global or address.is_multicast or address.is_unspecified or
                address.is_loopback or address.is_link_local or address.is_reserved):
            raise ValueError("Endpoint must resolve only to public internet addresses; private, local, multicast and reserved destinations are blocked.")
    return {
        "endpoint": raw, "host": host, "duration_seconds": duration_seconds,
        "aggregate_mbps": float(aggregate_mbps), "streams": streams,
        "max_total_mb": max_total_mb,
        "max_total_bytes": max_total_mb * 1024 * 1024,
        "profile": str(profile),
    }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _TokenBucket:
    """Shared pre-read rate gate; reservations are refunded for short reads."""
    def __init__(self, bytes_per_second):
        self.rate = max(1.0, float(bytes_per_second))
        self.capacity = max(CHUNK_SIZE, self.rate * 0.25)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, amount, stop_event):
        remaining = float(amount)
        while remaining > 0 and not stop_event.is_set():
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                taken = min(remaining, self.tokens)
                self.tokens -= taken
                remaining -= taken
            if remaining > 0:
                stop_event.wait(min(0.1, remaining / self.rate))
        return remaining <= 0 and not stop_event.is_set()

    def refund(self, amount):
        if amount <= 0:
            return
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + float(amount))
            self.updated = now


class NetworkLoadTestManager:
    """Runs one bounded, cancellable HTTPS download test from this host."""

    def __init__(self, opener_factory=None, resolver=None):
        self._opener_factory = opener_factory or (lambda: build_opener(_NoRedirect()))
        self._resolver = resolver
        self._lock = threading.RLock()
        self._job = None
        self._stop = None
        self._workers = []

    def status(self):
        with self._lock:
            if not self._job:
                return {"state": "IDLE", "available": True}
            job = dict(self._job)
            elapsed = max(0.001, (job.get("finished_at") or time.time()) - job["started_at"])
            job["elapsed_seconds"] = round(elapsed, 1)
            job["bytes_received"] = int(job.get("_bytes_received", 0))
            job["throughput_mbps"] = round(job["bytes_received"] * 8 / elapsed / 1_000_000, 3)
            job["max_total_bytes"] = int(job.get("max_total_bytes", MAX_TOTAL_BYTES))
            job["progress_percent"] = round(min(100, job["bytes_received"] / max(1, job["max_total_bytes"]) * 100), 1)
            job.pop("_bytes_received", None)
            job.pop("_bytes_reserved", None)
            job["available"] = True
            return job

    def start(self, endpoint, duration_seconds=30, aggregate_mbps=5,
              streams=2, max_total_mb=256, profile="Custom"):
        config = validate_test_config(
            endpoint, duration_seconds, aggregate_mbps, streams,
            max_total_mb, profile, self._resolver,
        )
        with self._lock:
            if self._job and self._job.get("state") in ("STARTING", "RUNNING", "STOPPING"):
                raise RuntimeError("A network load session is already active.")
            job_id = uuid.uuid4().hex[:12]
            stop_event = threading.Event()
            self._stop = stop_event
            self._job = {
                "job_id": job_id, "state": "STARTING",
                "endpoint_host": config["host"],
                "profile": config["profile"],
                "duration_seconds": config["duration_seconds"],
                "aggregate_mbps": config["aggregate_mbps"],
                "streams": config["streams"],
                "max_total_mb": config["max_total_mb"],
                "max_total_bytes": config["max_total_bytes"],
                "started_at": time.time(), "finished_at": None,
                "_bytes_received": 0, "_bytes_reserved": 0, "error": None,
            }
            bucket = _TokenBucket(config["aggregate_mbps"] * 1_000_000 / 8)
            self._workers = [
                threading.Thread(
                    target=self._worker,
                    args=(job_id, config, bucket, stop_event),
                    daemon=True, name=f"NetworkRadarWANLoad-{i+1}",
                )
                for i in range(config["streams"])
            ]
            for worker in self._workers:
                worker.start()
            self._job["state"] = "RUNNING"
            threading.Thread(
                target=self._supervise,
                args=(job_id, config["duration_seconds"], stop_event),
                daemon=True, name="NetworkRadarWANLoadSupervisor",
            ).start()
            return self.status()

    def _worker(self, job_id, config, bucket, stop_event):
        opener = self._opener_factory()
        deadline = time.monotonic() + config["duration_seconds"]
        try:
            while not stop_event.is_set() and time.monotonic() < deadline:
                request = Request(config["endpoint"], headers={
                    "User-Agent": "NetworkRadar/15.8 (authorised bounded bandwidth test)",
                    "Accept": "application/octet-stream,*/*;q=0.5",
                    "Cache-Control": "no-cache",
                }, method="GET")
                try:
                    with opener.open(request, timeout=3) as response:
                        if response.status < 200 or response.status >= 300:
                            raise RuntimeError(f"Endpoint returned HTTP {response.status}.")
                        while not stop_event.is_set() and time.monotonic() < deadline:
                            with self._lock:
                                job = self._job if self._job and self._job.get("job_id") == job_id else None
                                remaining = config["max_total_bytes"] - job["_bytes_received"] - job["_bytes_reserved"] if job else 0
                                read_size = min(CHUNK_SIZE, max(0, remaining))
                                if job and read_size:
                                    job["_bytes_reserved"] += read_size
                            if not read_size:
                                stop_event.set()
                                break
                            if not bucket.acquire(read_size, stop_event):
                                with self._lock:
                                    if self._job and self._job.get("job_id") == job_id:
                                        self._job["_bytes_reserved"] -= read_size
                                break
                            try:
                                chunk = response.read(read_size)
                            except Exception:
                                bucket.refund(read_size)
                                with self._lock:
                                    if self._job and self._job.get("job_id") == job_id:
                                        self._job["_bytes_reserved"] -= read_size
                                raise
                            actual = len(chunk or b"")
                            bucket.refund(read_size - actual)
                            with self._lock:
                                if self._job and self._job.get("job_id") == job_id:
                                    self._job["_bytes_reserved"] -= read_size
                                    self._job["_bytes_received"] += actual
                                    reached_cap = self._job["_bytes_received"] >= config["max_total_bytes"]
                                else:
                                    reached_cap = True
                            if not actual:
                                break
                            if reached_cap:
                                stop_event.set()
                                break
                            if stop_event.is_set():
                                break
                except Exception as exc:
                    if not stop_event.is_set():
                        raise RuntimeError(f"HTTPS download failed: {type(exc).__name__}: {str(exc)[:180]}") from exc
        except Exception as exc:
            with self._lock:
                if self._job and self._job.get("job_id") == job_id and not self._job.get("error"):
                    self._job["error"] = str(exc)[:300]
            stop_event.set()

    def _supervise(self, job_id, duration, stop_event):
        deadline = time.monotonic() + duration
        while not stop_event.is_set() and time.monotonic() < deadline:
            stop_event.wait(min(0.2, max(0.0, deadline - time.monotonic())))
        stop_event.set()
        for worker in list(self._workers):
            worker.join(timeout=4)
        with self._lock:
            if self._job and self._job.get("job_id") == job_id:
                if self._job["state"] != "STOPPING":
                    self._job["state"] = "FAILED" if self._job.get("error") else "COMPLETED"
                else:
                    self._job["state"] = "STOPPED"
                self._job["finished_at"] = time.time()

    def stop(self):
        with self._lock:
            if not self._job or self._job.get("state") not in ("STARTING", "RUNNING", "STOPPING"):
                return {"stopped": False, "message": "No active network-load session.", **self.status()}
            self._job["state"] = "STOPPING"
            if self._stop:
                self._stop.set()
        return {"stopped": True, **self.status()}


NETWORK_LOAD_TEST = NetworkLoadTestManager()
