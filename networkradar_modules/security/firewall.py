"""Read-only Windows Defender Firewall inventory and default-allow policy helpers.

This module never changes Windows Firewall configuration. The firewall
snapshot is collected in one bounded PowerShell process to avoid serial
process-start delays that can outlive the dashboard's request budget.
"""
from __future__ import annotations

import copy
import json
import platform
import subprocess
import threading
import time
from typing import Any


def default_device_decision(device: dict[str, Any] | None = None,
                            explicit_denials: set[str] | None = None) -> dict[str, str]:
    """Return ALLOW by default; only an explicit device/IP denial can block."""
    item = device or {}
    key = str(item.get("device_id") or item.get("ip") or "").strip()
    denied = {str(value).strip() for value in (explicit_denials or set())}
    if key and key in denied:
        return {"decision": "BLOCK", "reason": "Explicit operator deny policy."}
    return {"decision": "ALLOW", "reason": "Default policy: all discovered devices are allowed."}


def _run_powershell(command: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )


_FIREWALL_CACHE_LOCK = threading.RLock()
_FIREWALL_CACHE_DATA: dict[str, Any] | None = None
_FIREWALL_CACHE_AT = 0.0
_FIREWALL_CACHE_TTL_SECONDS = 30.0


def _collect_firewall_snapshot() -> dict[str, Any]:
    """Collect one read-only Windows Defender Firewall snapshot."""
    if platform.system().lower() != "windows":
        return {
            "supported": False, "status": "UNSUPPORTED",
            "message": "Windows Defender Firewall inspection is available on Windows.",
            "default_device_policy": "ALLOW", "automatic_blocking": False,
            "profiles": [], "rule_counts": {},
        }

    script = (
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "$p=@(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,"
        "DefaultInboundAction,DefaultOutboundAction,NotifyOnListen); "
        "$r=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop); "
        "$enabled=@($r | Where-Object {$_.Enabled -eq 'True'}); "
        "$in=@($enabled | Where-Object {$_.Direction -eq 'Inbound'}); "
        "$out=@($enabled | Where-Object {$_.Direction -eq 'Outbound'}); "
        "$block=@($enabled | Where-Object {$_.Action -eq 'Block'}); "
        "$allow=@($enabled | Where-Object {$_.Action -eq 'Allow'}); "
        "[pscustomobject]@{profiles=$p;rule_counts=[pscustomobject]@{"
        "total=$r.Count;enabled=$enabled.Count;inbound=$in.Count;"
        "outbound=$out.Count;block=$block.Count;allow=$allow.Count}} | "
        "ConvertTo-Json -Depth 6 -Compress"
    )
    result: dict[str, Any] = {
        "supported": True, "status": "DEGRADED",
        "default_device_policy": "ALLOW", "automatic_blocking": False,
        "profiles": [], "rule_counts": {},
        "message": "Firewall inspection has not completed.",
    }
    try:
        snapshot = _run_powershell(script, timeout=20)
        if snapshot.returncode != 0:
            raise RuntimeError(
                (snapshot.stderr or snapshot.stdout or "Firewall query failed")[-1200:]
            )
        data = json.loads(snapshot.stdout.strip() or "{}")
        raw_profiles = data.get("profiles", []) if isinstance(data, dict) else []
        if isinstance(raw_profiles, dict):
            raw_profiles = [raw_profiles]
        result["profiles"] = [
            {
                "name": str(row.get("Name", "")),
                "enabled": str(row.get("Enabled", "")).lower() == "true",
                "default_inbound_action": str(row.get("DefaultInboundAction", "Unknown")),
                "default_outbound_action": str(row.get("DefaultOutboundAction", "Unknown")),
                "notify_on_listen": str(row.get("NotifyOnListen", "")).lower() == "true",
            }
            for row in raw_profiles if isinstance(row, dict)
        ]
        counts = data.get("rule_counts", {}) if isinstance(data, dict) else {}
        result["rule_counts"] = counts if isinstance(counts, dict) else {}
        result["status"] = "ONLINE" if result["profiles"] else "DEGRADED"
        result["message"] = "Read-only Windows Defender Firewall inventory."
        result["collected_by"] = (
            "Get-NetFirewallProfile / Get-NetFirewallRule (single PowerShell process)"
        )
    except subprocess.TimeoutExpired:
        result["message"] = "Firewall inspection timed out; no settings were changed."
    except (OSError, ValueError, RuntimeError) as exc:
        result["message"] = str(exc)[:1200]
    return result


def get_firewall_snapshot(*, force: bool = False) -> dict[str, Any]:
    """Return a 30-second cached snapshot; manual refresh can request a new read.

    The dashboard polls every five seconds. Without this cache, every poll
    launches PowerShell and enumerates the full ActiveStore rule collection,
    which can take up to the 20-second subprocess timeout and stall refreshes.
    The lock also coalesces concurrent requests into one collection.
    """
    global _FIREWALL_CACHE_DATA, _FIREWALL_CACHE_AT
    with _FIREWALL_CACHE_LOCK:
        now = time.monotonic()
        age = max(0.0, now - _FIREWALL_CACHE_AT)
        if (
            not force
            and _FIREWALL_CACHE_DATA is not None
            and age < _FIREWALL_CACHE_TTL_SECONDS
        ):
            result = copy.deepcopy(_FIREWALL_CACHE_DATA)
            result["cached"] = True
            result["cache_age_seconds"] = int(age)
            return result

        snapshot = _collect_firewall_snapshot()
        _FIREWALL_CACHE_DATA = copy.deepcopy(snapshot)
        _FIREWALL_CACHE_AT = time.monotonic()
        result = copy.deepcopy(snapshot)
        result["cached"] = False
        result["cache_age_seconds"] = 0
        return result
