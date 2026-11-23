"""Evidence-weighted device identity fusion used by PHANTOM TRACK.

This module scores evidence, not devices in isolation. It preserves source
independence caps, freshness decay, conflict detection and conservative
auto-merge policy. A locally administered MAC is weak contextual evidence
only and is never an identity-merge anchor.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
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


def _bounded_strength(evidence: Mapping[str, Any]) -> float:
    """Convert untrusted evidence strength to a finite score in [0, 1]."""
    try:
        value = float(evidence.get("strength", 0.0) or 0.0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return min(1.0, max(0.0, value)) if math.isfinite(value) else 0.0


def freshness(observed_at: Any, now: datetime, half_life_days: float = DEFAULT_HALF_LIFE_DAYS) -> float:
    try:
        half_life = float(half_life_days)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("half_life_days must be a finite positive number") from exc
    if not math.isfinite(half_life) or half_life <= 0:
        raise ValueError("half_life_days must be a finite positive number")
    when = _parse_observed(observed_at)
    current = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    age_seconds = (current.astimezone(timezone.utc) - when).total_seconds()
    # Materially future-dated observations must not receive full freshness.
    if age_seconds < -300:
        return 0.0
    days = max(0.0, age_seconds / 86400.0)
    return 0.5 ** (days / half_life)


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
    if not isinstance(now, datetime):
        raise ValueError("now must be a datetime")
    try:
        cap = float(group_cap)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("group_cap must be a finite number in (0, 1]") from exc
    if not math.isfinite(cap) or not 0 < cap <= 1:
        raise ValueError("group_cap must be a finite number in (0, 1]")

    effective_thresholds = {}
    for key, default in DEFAULT_THRESHOLDS.items():
        try:
            value = float(thresholds.get(key, default))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"threshold {key} must be a finite number in [0, 1]") from exc
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"threshold {key} must be a finite number in [0, 1]")
        effective_thresholds[key] = value

    items = list(candidate or [])
    if not items:
        return "UNKNOWN", 0.0, {"reason": "no evidence"}

    by_kind: dict[str, set[str]] = {}
    groups: dict[str, float] = {}
    for evidence in items:
        group = str(evidence.get("independence_group", "unknown"))
        kind = str(evidence.get("kind", ""))
        strength = _bounded_strength(evidence)
        try:
            adjusted = strength * freshness(
                evidence.get("observed_at"), now, half_life_days
            )
        except (TypeError, ValueError, OverflowError):
            # Malformed timestamps are not usable identity evidence.
            continue

        # Stale evidence cannot create a current identity conflict. Use the
        # same freshness-adjusted strength threshold as the scoring path.
        if kind in conflict_kinds and adjusted >= 0.6:
            value = str(evidence.get("value", "")).strip().casefold()
            if value:
                by_kind.setdefault(kind, set()).add(value)

        if group == local_group:
            # A locally administered MAC is only a weak contextual signal;
            # even a fresh observation contributes no more than five points.
            groups[local_group] = max(
                groups.get(local_group, 0.0), min(adjusted, 0.05)
            )
            continue
        groups[group] = max(groups.get(group, 0.0), adjusted)

    conflicts = [
        {"kind": kind, "values": sorted(values)}
        for kind, values in by_kind.items() if len(values) > 1
    ]
    total = min(1.0, sum(min(value, cap) for value in groups.values()))
    if conflicts:
        outcome = "CONFLICTING_IDENTITY"
    elif total >= effective_thresholds["CONFIRMED_MATCH"]:
        outcome = "CONFIRMED_MATCH"
    elif total >= effective_thresholds["STRONG_MATCH"]:
        outcome = "STRONG_MATCH"
    elif total >= effective_thresholds["POSSIBLE_MATCH"]:
        outcome = "POSSIBLE_MATCH"
    elif total >= effective_thresholds["WEAK_MATCH"]:
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
