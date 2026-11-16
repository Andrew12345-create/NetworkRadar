"""Read-only Windows Defender Firewall inventory and default-allow policy helpers.

This module never changes Windows Firewall configuration. The firewall
snapshot is collected in one bounded PowerShell process to avoid serial
process-start delays that can outlive the dashboard's request budget.
"""
from __future__ import annotations

import json
import platform
import subprocess
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


def get_firewall_snapshot() -> dict[str, Any]:
    """Collect firewall profiles and rule counts in one read-only PowerShell call."""
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
