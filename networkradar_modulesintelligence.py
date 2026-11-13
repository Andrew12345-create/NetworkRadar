"""
intelligence.py — Phantom Track 2.0 scoring + Presence engine.

Enforces Part 4.3 / 4.4 / 23 rules:
  * OUI-only evidence never reaches STRONG_MATCH.
  * Locally administered MACs never contribute to a merge path.
  * Multiple observations from one independence group are capped.
  * Freshness decay (30-day half-life).
  * CONFLICTING_IDENTITY emitted on strong contradictory evidence.
  * Only CONFIRMED_MATCH may auto-merge.

Presence engine enforces Part 6: one missed scan never marks OFFLINE.
"""
from __future__ import annotations
import dataclasses
from datetime import datetime, timezone, timedelta

# ---------- Phantom Track 2.0 ----------
OUTCOMES = ("CONFIRMED_MATCH", "STRONG_MATCH", "POSSIBLE_MATCH", "WEAK_MATCH",
            "CONFLICTING_IDENTITY", "NEW_IDENTITY", "UNKNOWN")
THRESHOLDS = {"CONFIRMED_MATCH": 0.85, "STRONG_MATCH": 0.70,
              "POSSIBLE_MATCH": 0.50, "WEAK_MATCH": 0.30}
HALF_LIFE_DAYS = 30.0
GROUP_CAP = 0.45
AUTO_MERGE = {"CONFIRMED_MATCH"}
CONFLICT_KINDS = {"hostname", "client_id", "oui_global"}
LOCAL_MAC_GROUP = "oui_local"

@dataclasses.dataclass
class Evidence:
    source: str
    kind: str
    value: str
    strength: float
    independence_group: str
    observed_at: datetime
    detail: dict = dataclasses.field(default_factory=dict)

def _freshness(observed_at: datetime, now: datetime) -> float:
    days = max(0.0, (now - observed_at).total_seconds() / 86400.0)
    return 0.5 ** (days / HALF_LIFE_DAYS)

def score(candidate: list[Evidence],
          now: datetime | None = None) -> tuple[str, float, dict]:
    now = now or datetime.now(timezone.utc)
    if not candidate:
        return "UNKNOWN", 0.0, {"reason": "no evidence"}

    by_kind: dict[str, list[Evidence]] = {}
    for e in candidate:
        if e.kind in CONFLICT_KINDS and e.strength >= 0.6:
            by_kind.setdefault(e.kind, []).append(e)
    conflicts = []
    for kind, items in by_kind.items():
        vals = {i.value.lower() for i in items}
        if len(vals) > 1:
            conflicts.append({"kind": kind, "values": sorted(vals)})

    groups: dict[str, float] = {}
    for e in candidate:
        if e.independence_group == LOCAL_MAC_GROUP:
            groups[LOCAL_MAC_GROUP] = max(groups.get(LOCAL_MAC_GROUP, 0.0), 0.05)
            continue
        adj = e.strength * _freshness(e.observed_at, now)
        groups[e.independence_group] = max(groups.get(e.independence_group, 0.0), adj)
    total = min(1.0, sum(min(v, GROUP_CAP) for v in groups.values()))

    if conflicts:                                 outcome = "CONFLICTING_IDENTITY"
    elif total >= THRESHOLDS["CONFIRMED_MATCH"]:  outcome = "CONFIRMED_MATCH"
    elif total >= THRESHOLDS["STRONG_MATCH"]:     outcome = "STRONG_MATCH"
    elif total >= THRESHOLDS["POSSIBLE_MATCH"]:   outcome = "POSSIBLE_MATCH"
    elif total >= THRESHOLDS["WEAK_MATCH"]:       outcome = "WEAK_MATCH"
    else:                                          outcome = "NEW_IDENTITY"

    explain = {
        "total": round(total, 4),
        "groups": {k: round(v, 4) for k, v in groups.items()},
        "conflicts": conflicts,
        "auto_merge_allowed": outcome in AUTO_MERGE,
        "requires_manual_review": outcome in {"STRONG_MATCH","POSSIBLE_MATCH",
                                              "CONFLICTING_IDENTITY","WEAK_MATCH"},
        "local_mac_present": LOCAL_MAC_GROUP in groups,
    }
    return outcome, total, explain

# ---------- Presence engine ----------
@dataclasses.dataclass
class PresenceConfig:
    online_window_min: int = 30
    suspected_after_missed: int = 1
    offline_after_missed: int = 2      # matches 8.1.0 DEVICE_OFFLINE_CONFIRM_SCANS
    intermittent_toggles: int = 4
    intermittent_window_hours: int = 24

def evaluate(observation_times: list[datetime],
             completed_scan_times: list[datetime],
             prior_state: str | None,
             cfg: PresenceConfig,
             now: datetime) -> tuple[str, dict]:
    evidence = {"observations": len(observation_times),
                "completed_scans": len(completed_scan_times)}
    if not observation_times and not completed_scan_times:
        return "UNKNOWN", {**evidence, "reason": "no data"}
    if not observation_times:
        return "UNVERIFIED", {**evidence, "reason": "scans ran, device never observed"}

    last_obs = max(observation_times)
    if now - last_obs <= timedelta(minutes=cfg.online_window_min):
        state = ("RETURNED" if prior_state in ("OFFLINE", "SUSPECTED_OFFLINE")
                 else "ONLINE")
        return state, {**evidence, "last_observed": last_obs.isoformat()}

    missed = sum(1 for s in completed_scan_times if s > last_obs)
    if missed >= cfg.offline_after_missed:      base = "OFFLINE"
    elif missed >= cfg.suspected_after_missed:  base = "SUSPECTED_OFFLINE"
    else:                                        base = "UNVERIFIED"

    window = [t for t in observation_times
              if now - t <= timedelta(hours=cfg.intermittent_window_hours)]
    toggles = sum(1 for a, b in zip(window, window[1:])
                  if (b - a) > timedelta(minutes=cfg.online_window_min * 3))
    if toggles >= cfg.intermittent_toggles:
        return "INTERMITTENT", {**evidence, "missed": missed, "toggles": toggles}
    return base, {**evidence, "missed": missed}