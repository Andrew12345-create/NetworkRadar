"""Evidence reconciliation for stable, explainable NetworkRadar identity.

This module is deliberately pure: it does not probe hosts or access the database.
It distinguishes a fresh assessment from the accepted inventory identity, treats
missing observations as unknown (never negative), and prevents one weak scan
from replacing a better-supported historical classification.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


_PLACEHOLDERS = {"", "-", "unknown", "unavailable", "none", "n/a",
                 "unclassified", "unclassified network device",
                 "unidentified device"}


def _text(value: Any, limit: int = 240) -> str:
    return " ".join(str(value or "").split())[:limit]


def _is_classified(value: Any) -> bool:
    text = _text(value).casefold()
    return text not in _PLACEHOLDERS and not text.startswith(
        ("unclassified", "unidentified", "unknown", "ambiguous:")
    )


def _confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(float(value or 0))))
    except (TypeError, ValueError):
        return 0


def _parse_time(value: Any, now: datetime) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=now.tzinfo or timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    else:
        raw = _text(value, 80)
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    parsed = None
            if parsed is None:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=now.tzinfo or timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=parsed.tzinfo)
    return parsed


def evidence_freshness(observed_at: Any, *, now: datetime | None = None,
                       half_life_days: float = 14.0,
                       max_age_days: float = 90.0) -> dict[str, Any]:
    """Return a bounded freshness factor; unknown timestamps are not fresh."""
    now = now or datetime.now(timezone.utc)
    parsed = _parse_time(observed_at, now)
    if parsed is None:
        return {"factor": 0.0, "age_days": None, "state": "UNDATED"}
    age = max(0.0, (now - parsed).total_seconds() / 86400.0)
    if age > max(0.0, max_age_days):
        return {"factor": 0.0, "age_days": round(age, 2), "state": "EXPIRED"}
    half_life = max(0.1, float(half_life_days))
    factor = 0.5 ** (age / half_life)
    return {"factor": round(factor, 4), "age_days": round(age, 2),
            "state": "FRESH" if age <= 2 else "AGING"}


def _source_family(source: str) -> str:
    key = _text(source, 100).casefold()
    if key.startswith(("nmap", "tcp/ip", "passive tcp")):
        return "nmap_tcpip"
    if key.startswith(("dhcp", "bootp")):
        return "dhcp"
    if key.startswith(("mdns", "dns-sd")):
        return "mdns"
    if key.startswith(("ssdp", "upnp")):
        return "upnp"
    if key.startswith(("snmp",)):
        return "snmp"
    if key.startswith(("tls", "https certificate")):
        return "tls_certificate"
    if key.startswith(("ieee", "oui", "mac analysis")):
        return "mac_registry"
    if key.startswith(("endpoint", "authenticated endpoint")):
        return "endpoint_inventory"
    if key.startswith(("hostname", "reverse dns", "netbios")):
        return "name_resolution"
    return key.split(":", 1)[0] or "unknown"


def _row_parts(row: Any) -> tuple[str, str, str, int, str, str]:
    if isinstance(row, Mapping):
        return (
            _text(row.get("source"), 100), _text(row.get("attribute"), 100),
            _text(row.get("value") or row.get("observed_value"), 300),
            _confidence(row.get("confidence")),
            _text(row.get("evidence_class") or row.get("class") or "INFERRED", 40).upper(),
            _text(row.get("last_seen") or row.get("observed_at") or row.get("timestamp"), 80),
        )
    values = list(row or [])
    values += [""] * max(0, 6 - len(values))
    return (_text(values[0], 100), _text(values[1], 100),
            _text(values[2], 300), _confidence(values[3]),
            _text(values[4] or "INFERRED", 40).upper(),
            _text(values[5], 80))


def rank_evidence(evidence: Iterable[Any], *, now: datetime | None = None,
                  half_life_days: float = 14.0,
                  max_age_days: float = 90.0) -> dict[str, Any]:
    """Aggregate same-value evidence by independent source family.

    Repeated observations from one family contribute only their strongest
    freshness-adjusted score. Different values remain visible as conflicts.
    """
    now = now or datetime.now(timezone.utc)
    grouped: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    ignored = 0
    for raw in evidence or []:
        source, attribute, value, confidence, evidence_class, observed_at = _row_parts(raw)
        attribute = attribute.removeprefix("Identity observation:").strip()
        if not attribute or not value or value.casefold() in _PLACEHOLDERS:
            ignored += 1
            continue
        family = _source_family(source)
        freshness = evidence_freshness(
            observed_at, now=now, half_life_days=half_life_days,
            max_age_days=max_age_days,
        )
        reliability = {"DEVICE_REPORTED": 0.88, "OBSERVED": 0.82,
                       "INFERRED": 0.52}.get(evidence_class, 0.45)
        score = (confidence / 100.0) * reliability * freshness["factor"]
        key = (attribute.casefold(), value.casefold())
        candidate = grouped.setdefault(key, {})
        previous = candidate.get(family)
        item = {"source": source, "family": family, "value": value,
                "confidence": confidence, "evidence_class": evidence_class,
                "freshness": freshness, "score": round(score, 4)}
        if previous is None or item["score"] > previous["score"]:
            candidate[family] = item

    by_attribute: dict[str, list[dict[str, Any]]] = {}
    for (attribute, _), families in grouped.items():
        if not families:
            continue
        contributions = [row["score"] for row in families.values()]
        combined = 1.0
        for contribution in contributions:
            combined *= 1.0 - min(0.95, contribution)
        combined = min(0.97, combined + min(0.12, 0.035 * (len(contributions) - 1)))
        sample = max(families.values(), key=lambda row: (row["score"], row["confidence"]))
        by_attribute.setdefault(attribute, []).append({
            "attribute": attribute, "value": sample["value"],
            "confidence": round(combined * 100),
            "independent_sources": len(families),
            "sources": sorted({row["source"] for row in families.values()}),
            "evidence": list(families.values()),
        })

    results = {}
    for attribute, candidates in by_attribute.items():
        candidates.sort(key=lambda row: row["confidence"], reverse=True)
        best = candidates[0]
        runner = candidates[1] if len(candidates) > 1 else None
        best["conflict"] = bool(runner and runner["confidence"] >= 25
                                and best["confidence"] - runner["confidence"] < 18)
        best["competing_values"] = candidates[1:]
        results[attribute] = best
    return {"attributes": results, "evidence_count": sum(
        len(families) for families in grouped.values()), "ignored_count": ignored}


def reconcile_identity_assessment(current: Mapping[str, Any] | None,
                                  retained: Mapping[str, Any] | None,
                                  *, minimum_confidence: int = 58,
                                  replacement_margin: int = 8) -> dict[str, Any]:
    """Choose accepted inventory identity without hiding the current assessment."""
    current = current or {}
    retained = retained or {}
    current_type = _text(current.get("device_type") or current.get("category")
                         or current.get("selected_category"))
    current_conf = _confidence(current.get("confidence")
                               or current.get("identification_confidence"))
    retained_type = _text(retained.get("device_type") or retained.get("category"))
    retained_conf = _confidence(retained.get("identification_confidence")
                                or retained.get("confidence"))
    current_valid = _is_classified(current_type) and current_conf >= minimum_confidence
    retained_valid = _is_classified(retained_type) and retained_conf > 0

    if not current_valid:
        if retained_valid:
            action = "RETAINED_NO_NEW_EVIDENCE" if current_conf == 0 else "RETAINED_WEAKER_ASSESSMENT"
            accepted_type, accepted_conf = retained_type, retained_conf
        else:
            action, accepted_type, accepted_conf = "UNRESOLVED", (
                current_type if _is_classified(current_type) else "Unclassified network device"
            ), current_conf
    elif not retained_valid:
        action, accepted_type, accepted_conf = "ACCEPTED_NEW_IDENTITY", current_type, current_conf
    elif current_type.casefold() == retained_type.casefold():
        action = "REFRESHED_SAME_IDENTITY" if current_conf >= retained_conf else "RETAINED_STRONGER_SAME_IDENTITY"
        accepted_type = retained_type
        accepted_conf = max(current_conf, retained_conf)
    elif current_conf >= retained_conf + max(0, replacement_margin):
        action, accepted_type, accepted_conf = "REPLACED_WITH_STRONGER_EVIDENCE", current_type, current_conf
    else:
        action, accepted_type, accepted_conf = "RETAINED_CONFLICTING_IDENTITY", retained_type, retained_conf

    return {
        "current": {"device_type": current_type or "Unclassified network device",
                    "confidence": current_conf},
        "accepted": {"device_type": accepted_type, "confidence": accepted_conf},
        "previous": {"device_type": retained_type or "Unclassified network device",
                     "confidence": retained_conf},
        "action": action,
        "minimum_confidence": minimum_confidence,
        "replacement_margin": replacement_margin,
        "explanation": {
            "RETAINED_NO_NEW_EVIDENCE": "No current classification evidence was available; historical identity was preserved.",
            "RETAINED_WEAKER_ASSESSMENT": "The current assessment was below the acceptance threshold; historical identity was preserved.",
            "UNRESOLVED": "Neither current nor retained evidence establishes a device category.",
            "ACCEPTED_NEW_IDENTITY": "Current evidence established a category where no accepted identity existed.",
            "REFRESHED_SAME_IDENTITY": "Independent current evidence supports the existing category.",
            "RETAINED_STRONGER_SAME_IDENTITY": "The existing same-category assessment remains stronger.",
            "REPLACED_WITH_STRONGER_EVIDENCE": "The new category exceeded the retained confidence by the required margin.",
            "RETAINED_CONFLICTING_IDENTITY": "The competing category did not exceed the retained confidence by the required margin.",
        }[action],
    }


def plan_investigation_methods(device: Mapping[str, Any] | None,
                              evidence_sources: Iterable[str] | None = None,
                              attempts: Mapping[str, Any] | None = None,
                              *, authorised: bool = False,
                              now: datetime | None = None) -> dict[str, Any]:
    """Rank read-only evidence methods by availability and retry eligibility.

    This is a planner only. It never initiates network activity.
    """
    device, attempts = device or {}, attempts or {}
    now = now or datetime.now(timezone.utc)
    sources = " ".join(str(x).casefold() for x in (evidence_sources or []))
    online = str(device.get("status") or "ONLINE").upper() == "ONLINE"
    methods = [
        ("dhcp", "DHCP lease fingerprint", "DHCP", "PASSIVE",
         "Observe normal lease/renewal traffic; never force a lease renewal."),
        ("mdns", "mDNS/DNS-SD", "mDNS", "ACTIVE",
         "Browse only on an authorised network; correlate by source IP."),
        ("ssdp", "SSDP/UPnP", "SSDP", "ACTIVE",
         "Use bounded discovery and treat device-advertised fields as claims."),
        ("nmap", "TCP/OS/service fingerprint", "Nmap", "ACTIVE",
         "Use the existing bounded, authorised one-host fingerprint path."),
        ("snmp", "SNMPv3 read-only inventory", "SNMPv3", "CONFIGURED",
         "Use only explicitly configured read-only credentials; never guess credentials."),
        ("endpoint", "Authenticated endpoint inventory", "endpoint", "ENROLLED",
         "Enrol only a device administered by the operator."),
    ]
    planned, deferred = [], []
    for key, label, token, mode, reason in methods:
        if token.casefold() in sources or (key == "endpoint" and "agent inventory" in sources):
            deferred.append({"method": key, "state": "ALREADY_OBSERVED",
                             "reason": "Evidence from this method is already associated with the device."})
            continue
        attempt = attempts.get(key, {}) if isinstance(attempts.get(key, {}), Mapping) else {}
        try:
            attempt_count = max(0, int(attempt.get("attempts", 0) or 0))
        except (TypeError, ValueError):
            attempt_count = 0
        max_attempts = max(1, _confidence(attempt.get("max_attempts") or 3))
        next_at = _parse_time(attempt.get("next_eligible_at"), now)
        if str(attempt.get("state") or "").upper() == "RUNNING":
            deferred.append({"method": key, "state": "RUNNING",
                             "reason": "An investigation for this target is already in progress."})
            continue
        if str(attempt.get("state") or "").upper() in {"EXHAUSTED", "UNAVAILABLE"} or attempt_count >= max_attempts:
            deferred.append({"method": key, "state": "EXHAUSTED",
                             "reason": "The configured attempt budget is exhausted; wait for new evidence or a capability change."})
            continue
        if attempt_count > 0 and next_at and now < next_at:
            deferred.append({"method": key, "state": "COOLDOWN",
                             "next_eligible_at": next_at.isoformat(),
                             "reason": "A prior attempt is still in its retry cooldown."})
            continue
        if not online:
            deferred.append({"method": key, "state": "WAITING_FOR_ONLINE",
                             "reason": "Device is not currently online; do not spend an investigation attempt."})
            continue
        if mode in {"ACTIVE", "CONFIGURED"} and not authorised:
            deferred.append({"method": key, "state": "AUTHORIZATION_REQUIRED",
                             "reason": "Current network authorisation is required before active discovery."})
            continue
        if mode == "CONFIGURED" and not device.get("snmpv3_configured"):
            deferred.append({"method": key, "state": "CONFIGURATION_REQUIRED",
                             "reason": "SNMPv3 requires explicitly configured read-only credentials; no credentials are guessed."})
            continue
        if mode == "PASSIVE" and str(device.get("dhcp_capture_status", "")).upper() in {
            "UNAVAILABLE", "ERROR", "STOPPED", "NO_INTERFACE", "FAILED", "DEGRADED"
        }:
            deferred.append({"method": key, "state": "COLLECTOR_UNAVAILABLE",
                             "reason": "DHCP capture is unavailable; wait for a supported capture path instead of repeating an ineffective recommendation."})
            continue
        planned.append({"method": key, "label": label, "mode": mode, "reason": reason})
    return {"ip": _text(device.get("ip"), 64), "online": online,
            "authorised": bool(authorised), "planned": planned,
            "deferred": deferred,
            "note": "Planning only; no packets are sent and no credentials are attempted."}
