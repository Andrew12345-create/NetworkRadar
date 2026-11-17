"""Adaptive, evidence-aware scheduling for bounded Nmap fingerprinting.

This planner is deliberately pure: it performs no network I/O and makes no
authorisation decision. The caller must enforce current network authorisation
before invoking Nmap. A recent fingerprint attempt is cooled down so repeated full
scans do not spend most of their time re-probing unchanged, well-understood
hosts. New and weakly identified hosts receive priority.
"""
from __future__ import annotations

import ipaddress
import time
from datetime import datetime
from typing import Any, Mapping


def _epoch(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    text = str(value).strip()
    if not text:
        return None
    try:
        # now_text() is a local, timezone-naive timestamp; fromisoformat keeps
        # that local-time interpretation when timestamp() is called.
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _confidence(device: Mapping[str, Any]) -> int:
    value = device.get("identification_confidence")
    if value is None:
        profile = device.get("recognition") or device.get("identity_profile") or {}
        if isinstance(profile, Mapping):
            value = profile.get("confidence", 0)
    try:
        return max(0, min(100, int(float(value or 0))))
    except (TypeError, ValueError, OverflowError):
        return 0


def build_fingerprint_plan(
    devices: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    last_fingerprint_at: Mapping[str, Any] | None = None,
    *,
    now: float | None = None,
    max_targets: int = 8,
    max_udp_targets: int = 3,
    unknown_retry_seconds: int = 900,
    medium_refresh_seconds: int = 6 * 60 * 60,
    known_refresh_seconds: int = 24 * 60 * 60,
    allowed_network: str | None = None,
) -> dict[str, Any]:
    """Select the most useful private IPv4 targets without re-scanning all hosts.

    Priority order:
      1. No prior Nmap fingerprint attempt is recorded for this IP.
      2. Low-confidence identity whose last fingerprint is at least 15 minutes old.
      3. Medium-confidence identity whose fingerprint is at least 6 hours old.
      4. Higher-confidence identity whose fingerprint is at least 24 hours old.

    The timestamp is taken from port-scan observations (including incomplete
    attempts), not last_identified (which is refreshed by ordinary evidence fusion).
    """
    now = time.time() if now is None else float(now)
    history = last_fingerprint_at or {}
    limit = max(1, min(32, int(max_targets)))
    udp_limit = max(0, min(8, int(max_udp_targets)))
    candidates: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    seen: set[str] = set()
    scope = None
    if allowed_network is not None:
        try:
            scope = ipaddress.ip_network(str(allowed_network).strip(), strict=False)
        except ValueError:
            return {
                "targets": [], "udp_targets": [], "selected": [],
                "deferred": [{
                    "ip": str(item.get("ip") or "") if isinstance(item, Mapping) else "",
                    "priority": 0, "confidence": _confidence(item) if isinstance(item, Mapping) else 0,
                    "age_seconds": None,
                    "reason": "Current authorised subnet is missing or invalid; active fingerprinting fails closed.",
                } for item in (devices or [])],
                "candidate_count": 0, "deferred_count": len(devices or []),
                "max_targets": limit, "max_udp_targets": udp_limit,
                "policy": "scope validation failed; no active targets selected",
            }

    for raw in devices or []:
        if not isinstance(raw, Mapping):
            continue
        ip = str(raw.get("ip") or "").strip()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.version != 4 or not address.is_private or address.is_multicast or address.is_unspecified:
            continue
        if scope is not None and address not in scope:
            deferred.append({
                "ip": ip, "priority": 0, "confidence": _confidence(raw),
                "age_seconds": None,
                "reason": "Outside the current authorised subnet; active fingerprinting blocked.",
            })
            continue
        if ip in seen:
            continue
        seen.add(ip)

        last = _epoch(history.get(ip))
        age = None if last is None else max(0.0, now - last)
        confidence = _confidence(raw)
        if last is None:
            priority, reason = 100, "No prior Nmap fingerprint attempt is recorded"
        elif confidence < 58 and age >= max(60, int(unknown_retry_seconds)):
            priority, reason = 90, "Low-confidence identity is due for another bounded investigation"
        elif confidence < 58:
            priority, reason = 0, "Recently fingerprinted unknown; retry cooldown active"
        elif confidence < 80 and age >= max(300, int(medium_refresh_seconds)):
            priority, reason = 70, "Medium-confidence identity has stale fingerprint evidence"
        elif age >= max(600, int(known_refresh_seconds)):
            priority, reason = 55, "Known device fingerprint has reached its refresh interval"
        else:
            priority, reason = 0, "Recent fingerprint evidence remains within its refresh interval"

        item = {
            "ip": ip,
            "priority": priority,
            "confidence": confidence,
            "age_seconds": None if age is None else int(age),
            "reason": reason,
        }
        if priority:
            candidates.append(item)
        else:
            deferred.append(item)

    # Stable ordering makes runs reproducible and favours the oldest evidence
    # within a priority tier. New targets (age=None) remain first.
    candidates.sort(key=lambda item: (
        -item["priority"],
        -1 if item["age_seconds"] is None else -item["age_seconds"],
        int(ipaddress.ip_address(item["ip"])),
    ))
    selected = candidates[:limit]
    omitted = candidates[limit:]
    return {
        "targets": [item["ip"] for item in selected],
        "udp_targets": [item["ip"] for item in selected[:udp_limit]],
        "selected": selected,
        "deferred": deferred + [
            {**item, "reason": "Deferred by per-scan target budget"} for item in omitted
        ],
        "candidate_count": len(candidates),
        "deferred_count": len(deferred) + len(omitted),
        "max_targets": limit,
        "max_udp_targets": udp_limit,
        "scope": str(scope) if scope is not None else "not supplied by caller",
        "policy": "new-first; weak-identity retry 15m; medium refresh 6h; known refresh 24h",
    }
