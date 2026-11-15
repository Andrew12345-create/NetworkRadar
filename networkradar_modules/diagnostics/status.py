"""Normalise engine health without inventing activity or success."""
from __future__ import annotations


def engine_record(
    name: str,
    reported_status: str,
    *,
    last_error: str = "",
    configured: bool = True,
    details: dict | None = None,
) -> dict:
    """Return the established NetworkRadar engine-health response shape."""
    raw = str(reported_status or "UNKNOWN").upper()
    if not configured:
        state = "NOT_CONFIGURED"
    elif raw in {"RUNNING", "OBSERVING"}:
        # Process existence alone is not proof of successful observations.
        state = "DEGRADED" if last_error else "ONLINE"
    elif raw in {
        "ONLINE", "DEGRADED", "FAILED", "STOPPED", "STARTING",
        "DISABLED", "NOT_CONFIGURED",
    }:
        state = raw
    else:
        state = "UNKNOWN"
    return {
        "engine": str(name),
        "status": state,
        "reported_status": raw,
        "last_error": str(last_error or "")[:500],
        "details": details or {},
    }
