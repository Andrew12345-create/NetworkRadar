"""Evidence-weighted device identity fusion used by PHANTOM TRACK.

This module scores evidence, not devices in isolation. It preserves source
independence caps, freshness decay, conflict detection and conservative
auto-merge policy. A locally administered MAC is weak contextual evidence
only and is never an identity-merge anchor.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping, Any

DEFAULT_THRESHOLDS = {
    "CONFIRMED_MATCH": 0.85,
    "STRONG_MATCH": 0.70,
    "POSSIBLE_MATCH": 0.50,
    "WEAK_MATCH": 0.30,
}
DEFAULT_HALF_LIFE_DAYS = 30.0
DEFAULT_GROUP_CAP = 0.45
DEFAULT_AUTO_MERGE = frozenset({"CONFIRMED_MATCH"})
DEFAULT_CONFLICT_KINDS = frozenset({"hostname", "client_id", "oui_global"})
DEFAULT_LOCAL_GROUP = "oui_local"


def _parse_observed(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value or "").strip()
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            # Existing NetworkRadar rows use second-resolution local text.
            dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def freshness(observed_at: Any, now: datetime, half_life_days: float = DEFAULT_HALF_LIFE_DAYS) -> float:
    if half_life_days <= 0:
        raise ValueError("half_life_days must be positive")
    when = _parse_observed(observed_at)
    current = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    age_seconds = (current.astimezone(timezone.utc) - when).total_seconds()
    # Materially future-dated observations must not receive full freshness.
    if age_seconds < -300:
        return 0.0
    days = max(0.0, age_seconds / 86400.0)
    return 0.5 ** (days / half_life_days)


def score_evidence(
    candidate: Iterable[Mapping[str, Any]] | None,
    *,
    now: datetime | None = None,
    thresholds: Mapping[str, float] = DEFAULT_THRESHOLDS,
    half_life_days: float = DEFAULT_HALF_LIFE_DAYS,
    group_cap: float = DEFAULT_GROUP_CAP,
    auto_merge: frozenset[str] = DEFAULT_AUTO_MERGE,
    conflict_kinds: frozenset[str] = DEFAULT_CONFLICT_KINDS,
    local_group: str = DEFAULT_LOCAL_GROUP,
) -> tuple[str, float, dict]:
    now = now or datetime.now(timezone.utc)
    items = list(candidate or [])
    if not items:
        return "UNKNOWN", 0.0, {"reason": "no evidence"}

    by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for evidence in items:
        kind = str(evidence.get("kind", ""))
        strength = max(0.0, min(1.0, float(evidence.get("strength", 0.0) or 0.0)))
        if kind in conflict_kinds and strength >= 0.6:
            by_kind.setdefault(kind, []).append(evidence)

    conflicts = []
    for kind, observations in by_kind.items():
        values = {
            str(obs.get("value", "")).strip().casefold()
            for obs in observations if str(obs.get("value", "")).strip()
        }
        if len(values) > 1:
            conflicts.append({"kind": kind, "values": sorted(values)})

    groups: dict[str, float] = {}
    for evidence in items:
        group = str(evidence.get("independence_group", "unknown"))
        if group == local_group:
            groups[local_group] = max(groups.get(local_group, 0.0), 0.05)
            continue
        strength = max(0.0, min(1.0, float(evidence.get("strength", 0.0) or 0.0)))
        try:
            adjusted = strength * freshness(
                evidence.get("observed_at"), now, half_life_days
            )
        except (TypeError, ValueError, OverflowError):
            # Malformed timestamps are not usable identity evidence.
            continue
        groups[group] = max(groups.get(group, 0.0), adjusted)

    total = min(1.0, sum(min(value, group_cap) for value in groups.values()))
    if conflicts:
        outcome = "CONFLICTING_IDENTITY"
    elif total >= thresholds["CONFIRMED_MATCH"]:
        outcome = "CONFIRMED_MATCH"
    elif total >= thresholds["STRONG_MATCH"]:
        outcome = "STRONG_MATCH"
    elif total >= thresholds["POSSIBLE_MATCH"]:
        outcome = "POSSIBLE_MATCH"
    elif total >= thresholds["WEAK_MATCH"]:
        outcome = "WEAK_MATCH"
    else:
        outcome = "NEW_IDENTITY"

    explanation = {
        "total": round(total, 4),
        "groups": {key: round(value, 4) for key, value in groups.items()},
        "conflicts": conflicts,
        "auto_merge_allowed": outcome in auto_merge,
        "requires_manual_review": outcome in {
            "STRONG_MATCH", "POSSIBLE_MATCH", "CONFLICTING_IDENTITY", "WEAK_MATCH"
        },
        "local_mac_present": local_group in groups,
    }
    return outcome, total, explanation
