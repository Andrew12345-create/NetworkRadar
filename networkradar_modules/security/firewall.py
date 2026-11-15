"""Read-only Windows Defender Firewall inventory and default-allow policy helpers.

This module deliberately does not change Windows Firewall configuration.
NetworkRadar's device policy is ALLOW unless an operator explicitly adds a
deny decision in a future, audited enforcement layer. The OS firewall protects
the host running NetworkRadar; it does not control every LAN device.
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


def _run_powershell(command: str, timeout: int = 12) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )


def get_firewall_snapshot() -> dict[str, Any]:
    """Collect firewall profile state and rule counts without modifying anything."""
    if platform.system().lower() != "windows":
        return {
            "supported": False, "status": "UNSUPPORTED",
            "message": "Windows Defender Firewall inspection is available on Windows.",
            "default_device_policy": "ALLOW", "automatic_blocking": False,
            "profiles": [], "rule_counts": {},
        }

    profile_script = (
        "Get-NetFirewallProfile | Select-Object Name,Enabled,"
        "DefaultInboundAction,DefaultOutboundAction,NotifyOnListen | "
        "ConvertTo-Json -Compress"
    )
    rules_script = (
        "$r=Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop; "
        "$enabled=@($r | Where-Object {$_.Enabled -eq 'True'}); "
        "$in=@($enabled | Where-Object {$_.Direction -eq 'Inbound'}); "
        "$out=@($enabled | Where-Object {$_.Direction -eq 'Outbound'}); "
        "$block=@($enabled | Where-Object {$_.Action -eq 'Block'}); "
        "$allow=@($enabled | Where-Object {$_.Action -eq 'Allow'}); "
        "[pscustomobject]@{total=$r.Count;enabled=$enabled.Count;"
        "inbound=$in.Count;outbound=$out.Count;block=$block.Count;allow=$allow.Count} | "
        "ConvertTo-Json -Compress"
    )
    result: dict[str, Any] = {
        "supported": True, "status": "DEGRADED",
        "default_device_policy": "ALLOW", "automatic_blocking": False,
        "profiles": [], "rule_counts": {},
        "message": "Firewall inspection has not completed.",
    }
    try:
        profiles = _run_powershell(profile_script)
        if profiles.returncode != 0:
            raise RuntimeError((profiles.stderr or profiles.stdout or "Profile query failed")[-1200:])
        raw_profiles = json.loads(profiles.stdout.strip() or "[]")
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
        rules = _run_powershell(rules_script)
        if rules.returncode != 0:
            raise RuntimeError((rules.stderr or rules.stdout or "Rule query failed")[-1200:])
        counts = json.loads(rules.stdout.strip() or "{}")
        result["rule_counts"] = counts if isinstance(counts, dict) else {}
        result["status"] = "ONLINE" if result["profiles"] else "DEGRADED"
        result["message"] = "Read-only Windows Defender Firewall inventory."
        result["collected_by"] = "Get-NetFirewallProfile / Get-NetFirewallRule"
    except subprocess.TimeoutExpired:
        result["message"] = "Firewall inspection timed out; no settings were changed."
    except (OSError, ValueError, RuntimeError) as exc:
        result["message"] = str(exc)[:1200]
    return result
