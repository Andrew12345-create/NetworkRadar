"""Continuous, bounded follow-up scheduling for unidentified devices.

The coordinator is deliberately a scheduler, not a scanner. It deduplicates
targets, uses evidence-change detection and exponential backoff, and caps
retries so an unresponsive endpoint cannot be probed indefinitely.
"""
from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
from typing import Any, Iterable, Mapping


class IdentitySubscanCoordinator:
    """Thread-safe one-at-a-time queue for authorised device follow-up scans."""

    def __init__(self, *, max_attempts: int = 3, base_backoff: float = 90.0,
                 max_backoff: float = 3600.0, exhausted_cooldown: float = 21600.0):
        self.max_attempts = max(1, int(max_attempts))
        self.base_backoff = max(1.0, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        self.exhausted_cooldown = max(self.max_backoff, float(exhausted_cooldown))
        self._lock = threading.RLock()
        self._items: dict[str, dict[str, Any]] = {}
        self._active_key: str | None = None
        self._paused = False
        self._started_at = time.time()
        self._counts = {"queued": 0, "running": 0, "resolved": 0,
                        "exhausted": 0, "deferred": 0}
        self._progress = {
            "state": "IDLE", "ip": "", "phase": "Waiting for an unidentified device.",
            "percent": 0, "message": "No identity subscan is currently running.",
            "started_at": None, "updated_at": time.time(),
        }
        self._last_result: dict[str, Any] = {}

    @staticmethod
    def _key(device: Mapping[str, Any]) -> str:
        mac = str(device.get("mac") or "").strip().casefold()
        ip = str(device.get("ip") or "").strip()
        # MAC is a stronger queue anchor where available; IP remains workspace-scoped.
        return "mac:" + mac if mac and mac not in {"unavailable", "00:00:00:00:00:00"} else "ip:" + ip

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
        unresolved = (
            confidence < 65
            or "unclass" in category
            or "unknown" in category
            or "unident" in name
            or not category
        )
        return unresolved

    def observe(self, devices: Iterable[Mapping[str, Any]], *, now: float | None = None) -> int:
        """Queue or refresh currently observed unidentified devices."""
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
                if key in {"mac:", "ip:"}:
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
                    existing["last_observed"] = now
                    if existing["signature"] != signature and existing["state"] in {"EXHAUSTED", "RESOLVED"}:
                        existing.update({
                            "signature": signature, "attempts": 0, "state": "QUEUED",
                            "next_attempt_at": now, "last_error": "",
                        })
                        added += 1
                    elif existing["state"] == "EXHAUSTED" and now >= existing.get("cooldown_until", 0):
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
                }
                added += 1
            self._refresh_counts()
        return added

    def claim_due(self, *, now: float | None = None) -> dict[str, Any] | None:
        """Claim at most one due target. The caller must complete/fail the claim."""
        now = time.time() if now is None else float(now)
        with self._lock:
            if self._paused or self._active_key:
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
            self._active_key = item["key"]
            self._progress = {
                "state": "RUNNING", "ip": item["ip"],
                "phase": "Preparing targeted investigation", "percent": 3,
                "message": "Checking current authorisation and device availability.",
                "started_at": now, "updated_at": now,
            }
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
            if self._active_key == key:
                self._active_key = None
            self._progress = {
                "state": "COMPLETED" if recognised else item["state"],
                "ip": item["ip"],
                "phase": "Identity assessment complete" if recognised else "Investigation attempt complete",
                "percent": 100,
                "message": ("Device identity now meets the recognition threshold."
                            if recognised else item["last_error"] or "No conclusive new identity evidence."),
                "started_at": self._progress.get("started_at"),
                "updated_at": now,
                "completed_at": now,
            }
            self._last_result = dict(self._progress)
            self._refresh_counts()
            return dict(item)

    def update_progress(self, key: str, phase: str, percent: int,
                        message: str = "", *, now: float | None = None) -> None:
        """Update the independent progress state for the currently claimed host."""
        now = time.time() if now is None else float(now)
        with self._lock:
            if self._active_key != key:
                return
            self._progress.update({
                "state": "RUNNING",
                "phase": str(phase or "Investigating")[:100],
                "percent": max(int(self._progress.get("percent", 0)),
                               min(99, max(0, int(percent)))),
                "message": str(message or "")[:240],
                "updated_at": now,
            })

    def defer_active(self, reason: str = "Deferred by scheduler", *, now: float | None = None) -> None:
        now = time.time() if now is None else float(now)
        with self._lock:
            if not self._active_key:
                return
            item = self._items.get(self._active_key)
            if item:
                item["state"] = "QUEUED"
                item["attempts"] = max(0, item["attempts"] - 1)
                item["next_attempt_at"] = now + self.base_backoff
                item["last_error"] = str(reason)[:240]
            self._active_key = None
            self._progress = {
                "state": "DEFERRED", "ip": item["ip"] if item else "",
                "phase": "Waiting for main scan", "percent": 0,
                "message": str(reason)[:240], "started_at": None,
                "updated_at": now,
            }
            self._refresh_counts()

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
            processed = self._counts["resolved"] + self._counts["exhausted"]
            total = len(items)
            attempted_targets = sum(1 for item in items if int(item.get("attempts", 0)) > 0)
            total_attempts = sum(int(item.get("attempts", 0)) for item in items)
            return {
                "enabled": not self._paused,
                "paused": self._paused,
                "worker_alive": bool(getattr(self, "_worker_alive", False)),
                "active_key": self._active_key,
                "counts": dict(self._counts),
                "total_targets": total,
                "processed_targets": processed,
                "attempted_targets": attempted_targets,
                "total_attempts": total_attempts,
                "unattempted_targets": max(0, total - attempted_targets),
                "queue_progress_percent": round((processed / total) * 100) if total else 0,
                "progress": dict(self._progress),
                "last_result": dict(self._last_result),
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
