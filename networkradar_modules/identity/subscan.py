"""Continuous, bounded and parallel follow-up scheduling for unidentified devices.

The coordinator schedules one-host investigations, maintains independent
progress per target, and never treats a locally administered MAC as a durable
cross-IP identity anchor.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from typing import Any, Iterable, Mapping


class IdentitySubscanCoordinator:
    """Thread-safe bounded queue supporting a small pool of concurrent workers."""

    def __init__(self, *, max_attempts: int = 3, max_workers: int = 3,
                 base_backoff: float = 90.0, max_backoff: float = 3600.0,
                 exhausted_cooldown: float = 21600.0):
        self.max_attempts = max(1, int(max_attempts))
        try:
            workers = int(max_workers)
        except (TypeError, ValueError):
            workers = 3
        self.max_workers = min(5, max(1, workers))
        self.base_backoff = max(1.0, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        self.exhausted_cooldown = max(self.max_backoff, float(exhausted_cooldown))
        self._lock = threading.RLock()
        self._items: dict[str, dict[str, Any]] = {}
        self._active: dict[str, dict[str, Any]] = {}
        self._paused = False
        self._started_at = time.time()
        self._counts = {"queued": 0, "running": 0, "resolved": 0,
                        "exhausted": 0, "deferred": 0}
        self._last_result: dict[str, Any] = {}
        self._worker_alive = False

    @staticmethod
    def _global_mac(value: Any) -> str:
        mac = str(value or "").strip().upper().replace("-", ":")
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            return ""
        octet = int(mac[:2], 16)
        if (octet & 1) or (octet & 2) or mac in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
            return ""
        return mac

    @classmethod
    def _key(cls, device: Mapping[str, Any]) -> str:
        mac = cls._global_mac(device.get("mac"))
        ip = str(device.get("ip") or "").strip()
        # Only globally administered unicast MACs can anchor a cross-IP queue item.
        return "mac:" + mac if mac else "ip:" + ip

    @staticmethod
    def _signature(device: Mapping[str, Any]) -> str:
        fields = (
            device.get("mac"), device.get("hostname"), device.get("device_name"),
            device.get("device_type"), device.get("os_guess"), device.get("open_ports"),
            device.get("manufacturer"), device.get("identification_methods"),
        )
        raw = "|".join(str(value or "").strip().casefold() for value in fields)
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:20]

    @staticmethod
    def is_unidentified(device: Mapping[str, Any]) -> bool:
        try:
            confidence = int(device.get("identification_confidence") or device.get("confidence") or 0)
        except (TypeError, ValueError):
            confidence = 0
        category = str(device.get("device_type") or "").casefold()
        name = str(device.get("device_name") or device.get("name") or "").casefold()
        return (
            confidence < 65
            or "unclass" in category
            or "unknown" in category
            or "unident" in name
            or not category
        )

    def observe(self, devices: Iterable[Mapping[str, Any]], *, now: float | None = None) -> int:
        """Queue currently observed unidentified private IPv4 devices."""
        now = time.time() if now is None else float(now)
        added = 0
        with self._lock:
            for raw in devices or []:
                device = dict(raw)
                ip = str(device.get("ip") or "").strip()
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if address.version != 4 or not address.is_private or address.is_multicast or address.is_unspecified:
                    continue
                key = self._key(device)
                if key == "ip:":
                    continue
                signature = self._signature(device)
                existing = self._items.get(key)
                if not self.is_unidentified(device):
                    if existing and existing["state"] in {"QUEUED", "EXHAUSTED"}:
                        existing.update({"device": device, "signature": signature,
                                         "state": "RESOLVED", "next_attempt_at": None,
                                         "cooldown_until": None, "last_error": ""})
                    continue
                if existing:
                    existing["device"] = device
                    existing["ip"] = ip
                    existing["last_observed"] = now
                    if existing["signature"] != signature and existing["state"] in {"EXHAUSTED", "RESOLVED"}:
                        existing.update({"signature": signature, "attempts": 0, "state": "QUEUED",
                                         "next_attempt_at": now, "last_error": ""})
                        added += 1
                    elif existing["state"] == "EXHAUSTED" and now >= (existing.get("cooldown_until") or 0):
                        existing.update({"attempts": 0, "state": "QUEUED",
                                         "next_attempt_at": now, "last_error": ""})
                        added += 1
                    continue
                self._items[key] = {
                    "key": key, "ip": ip, "device": device, "signature": signature,
                    "state": "QUEUED", "attempts": 0, "created_at": now,
                    "last_observed": now, "next_attempt_at": now,
                    "last_attempt_at": None, "last_completed_at": None,
                    "last_error": "", "cooldown_until": None,
                    "progress": {"state": "QUEUED", "ip": ip, "phase": "Waiting in queue",
                                 "percent": 0, "message": "Awaiting an available investigation worker."},
                }
                added += 1
            self._refresh_counts()
        return added

    def claim_due(self, *, now: float | None = None) -> dict[str, Any] | None:
        """Claim one due target if a worker slot is available."""
        now = time.time() if now is None else float(now)
        with self._lock:
            if self._paused or len(self._active) >= self.max_workers:
                return None
            due = [
                item for item in self._items.values()
                if item["state"] == "QUEUED" and item["next_attempt_at"] <= now
            ]
            if not due:
                return None
            due.sort(key=lambda item: (item["next_attempt_at"], item["attempts"], item["created_at"]))
            item = due[0]
            item["state"] = "RUNNING"
            item["attempts"] += 1
            item["last_attempt_at"] = now
            item["progress"] = {
                "state": "RUNNING", "ip": item["ip"], "phase": "Preparing targeted investigation",
                "percent": 3, "message": "Checking current authorisation and device availability.",
                "started_at": now, "updated_at": now,
            }
            self._active[item["key"]] = item
            self._refresh_counts()
            return dict(item)

    def complete(self, key: str, *, recognised: bool, error: str = "",
                 now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else float(now)
        with self._lock:
            item = self._items.get(key)
            if not item:
                return {"state": "MISSING"}
            item["last_completed_at"] = now
            item["last_error"] = str(error or "")[:240]
            if recognised:
                item["state"] = "RESOLVED"
                item["next_attempt_at"] = None
                item["cooldown_until"] = None
            elif item["attempts"] >= self.max_attempts:
                item["state"] = "EXHAUSTED"
                item["next_attempt_at"] = None
                item["cooldown_until"] = now + self.exhausted_cooldown
            else:
                item["state"] = "QUEUED"
                delay = min(self.max_backoff, self.base_backoff * (2 ** (item["attempts"] - 1)))
                item["next_attempt_at"] = now + delay
            self._active.pop(key, None)
            progress = {
                "state": "COMPLETED" if recognised else item["state"],
                "ip": item["ip"],
                "phase": "Identity assessment complete" if recognised else "Investigation attempt complete",
                "percent": 100,
                "message": ("Device identity now meets the recognition threshold."
                            if recognised else item["last_error"] or "No conclusive new identity evidence."),
                "started_at": item.get("progress", {}).get("started_at"),
                "updated_at": now,
                "completed_at": now,
            }
            item["progress"] = progress
            self._last_result = dict(progress)
            self._refresh_counts()
            return dict(item)

    def update_progress(self, key: str, phase: str, percent: int,
                        message: str = "", *, now: float | None = None) -> None:
        now = time.time() if now is None else float(now)
        with self._lock:
            item = self._active.get(key)
            if not item:
                return
            old = item.get("progress", {})
            item["progress"] = {
                **old, "state": "RUNNING", "ip": item["ip"],
                "phase": str(phase or "Investigating")[:100],
                "percent": max(int(old.get("percent", 0)),
                               min(99, max(0, int(percent)))),
                "message": str(message or "")[:240], "updated_at": now,
            }

    def defer(self, key: str, reason: str = "Deferred by scheduler", *,
              delay_seconds: float | None = None, now: float | None = None) -> None:
        """Return a claimed target to the queue without consuming an attempt."""
        now = time.time() if now is None else float(now)
        with self._lock:
            item = self._active.pop(key, None)
            if not item:
                return
            item["state"] = "QUEUED"
            item["attempts"] = max(0, item["attempts"] - 1)
            delay = self.base_backoff if delay_seconds is None else max(1.0, float(delay_seconds))
            item["next_attempt_at"] = now + min(self.max_backoff, delay)
            item["last_error"] = str(reason)[:240]
            item["progress"] = {
                "state": "QUEUED", "ip": item["ip"], "phase": "Waiting for worker capacity",
                "percent": 0, "message": item["last_error"], "updated_at": now,
            }
            self._refresh_counts()

    def defer_active(self, reason: str = "Deferred by scheduler", *, now: float | None = None) -> None:
        with self._lock:
            keys = list(self._active)
        for key in keys:
            self.defer(key, reason, now=now)

    def pause(self) -> None:
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        with self._lock:
            self._paused = False

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else float(now)
        with self._lock:
            self._refresh_counts()
            items = sorted(self._items.values(),
                           key=lambda item: (item["state"], item["next_attempt_at"] or float("inf")))
            active = sorted(self._active.values(), key=lambda item: item.get("last_attempt_at") or 0)
            processed = self._counts["resolved"] + self._counts["exhausted"]
            total = len(items)
            active_rows = [{
                "key": item["key"], "ip": item["ip"], "attempts": item["attempts"],
                "progress": dict(item.get("progress") or {}),
            } for item in active]
            progress = dict(active[0].get("progress") or {}) if active else dict(self._last_result)
            return {
                "enabled": not self._paused, "paused": self._paused,
                "worker_alive": self._worker_alive,
                "active_key": active[0]["key"] if active else None,
                "active_investigations": active_rows,
                "active_worker_count": len(active),
                "max_workers": self.max_workers,
                "counts": dict(self._counts),
                "total_targets": total, "processed_targets": processed,
                "queue_progress_percent": round((processed / total) * 100) if total else 0,
                "progress": progress, "last_result": dict(self._last_result),
                "max_attempts_per_target": self.max_attempts,
                "next_due_in_seconds": min(
                    (max(0.0, item["next_attempt_at"] - now)
                     for item in items if item["state"] == "QUEUED"),
                    default=None,
                ),
                "targets": [{
                    "key": item["key"], "ip": item["ip"], "state": item["state"],
                    "attempts": item["attempts"], "last_error": item["last_error"],
                    "next_attempt_at": item["next_attempt_at"],
                    "last_completed_at": item["last_completed_at"],
                } for item in items[:100]],
            }

    def set_worker_alive(self, alive: bool) -> None:
        with self._lock:
            self._worker_alive = bool(alive)

    def _refresh_counts(self) -> None:
        counts = {"queued": 0, "running": 0, "resolved": 0,
                  "exhausted": 0, "deferred": 0}
        for item in self._items.values():
            state = item["state"]
            if state == "QUEUED":
                counts["queued"] += 1
            elif state == "RUNNING":
                counts["running"] += 1
            elif state == "RESOLVED":
                counts["resolved"] += 1
            elif state == "EXHAUSTED":
                counts["exhausted"] += 1
        self._counts = counts
