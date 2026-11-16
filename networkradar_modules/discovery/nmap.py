"""Nmap host-discovery execution and XML parsing.

This module contains no application globals. Callers must supply the network
scope and executable path; the application remains responsible for deciding
whether the selected network is authorised before invoking active discovery.
"""
from __future__ import annotations

import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Sequence


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Parse Nmap -sn XML into the stable NetworkRadar device-record shape."""
    root = ET.fromstring(xml_text)
    devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip, mac, vendor, hostname = "", "Unavailable", "Unknown", "-"
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr", "")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr", "Unavailable")
                vendor = address.get("vendor") or "Unknown"
        names = host.find("hostnames")
        if names is not None:
            candidates = [
                node.get("name") for node in names.findall("hostname")
                if node.get("name")
            ]
            if candidates:
                hostname = candidates[0]
        if ip:
            status_reason = status.get("reason", "") if status is not None else ""
            mac_valid = mac not in ("", "Unavailable")
            locally_administered = False
            if mac_valid:
                try:
                    locally_administered = bool(int(mac.split(":")[0], 16) & 0x02)
                except (ValueError, IndexError):
                    locally_administered = False
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "device_name": hostname if hostname != "-" else "",
                "friendly_name": "",
                "device_type": "Unclassified device",
                "os_guess": "Unknown",
                "model": "",
                "identification_confidence": 0,
                "identification_methods": "",
                "open_ports": "",
                "service_summary": "",
                "discovery_method": "Nmap host discovery",
                "discovery_reason": status_reason,
                "mac_address_scope": (
                    "locally administered" if locally_administered else
                    "globally administered" if mac_valid else "unknown"
                ),
                "mac_identity_note": (
                    "May be randomized or locally assigned; not a stable factory identity."
                    if locally_administered else ""
                ),
                "discovery_sources": ["Nmap"],
            })
    return devices


def run_nmap_discovery(
    network: str,
    executable: str | Path,
    log_path: str | Path,
    *,
    timeout: float = 150,
    runner: Callable = subprocess.run,
) -> tuple[list[dict], float]:
    """Run a bounded Nmap ping scan and return parsed devices and duration."""
    if not network:
        return [], 0.0
    # Explicit ARP discovery is more reliable than ICMP on a directly
    # attached Ethernet/Wi-Fi LAN. Disable reverse DNS here to avoid slow
    # resolver lookups for every address; hostname enrichment runs separately.
    command: Sequence[str] = (
        str(executable), "-sn", "-PR", "-n", "--reason", "-oX", "-", str(network)
    )
    started = time.time()
    primary_error = ""
    primary_stdout = ""
    try:
        result = runner(
            list(command),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        primary_stdout = result.stdout or ""
        primary_error = (result.stderr or "")[-1000:]
        devices = parse_nmap_xml(primary_stdout) if result.returncode == 0 else []
        if result.returncode != 0 and not primary_error:
            primary_error = f"Nmap ARP discovery exited with code {result.returncode}."
    except Exception as exc:
        devices = []
        primary_error = str(exc)[:1000]

    # If raw ARP discovery is unavailable (for example, Npcap permissions),
    # retry using Nmap's ordinary host-discovery probes. This keeps scans
    # functional for non-elevated launches without silently claiming ARP worked.
    fallback_error = ""
    fallback_stdout = ""
    if not devices:
        fallback_command = (
            str(executable), "-sn", "-n", "--reason", "-oX", "-", str(network)
        )
        try:
            fallback = runner(
                list(fallback_command),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            fallback_stdout = fallback.stdout or ""
            fallback_error = (fallback.stderr or "")[-1000:]
            if fallback.returncode != 0:
                raise RuntimeError(fallback_error or f"Nmap fallback exited with code {fallback.returncode}.")
            devices = parse_nmap_xml(fallback_stdout)
        except Exception as exc:
            fallback_error = str(exc)[:1000]
            Path(log_path).write_text(
                "ARP discovery error: " + primary_error + "\nFallback error: " +
                fallback_error + "\n" + primary_stdout[:1000] + fallback_stdout[:1000],
                encoding="utf-8",
            )
            raise RuntimeError(
                "Nmap ARP discovery and fallback both failed. ARP: " +
                (primary_error or "no hosts returned") + "; fallback: " +
                fallback_error[-500:]
            ) from exc

    duration = round(time.time() - started, 2)
    log_text = (
        "ARP discovery stderr: " + primary_error + "\n" +
        "Fallback stderr: " + fallback_error + "\n" +
        (primary_stdout[:1000] + fallback_stdout[:1000])
    )
    Path(log_path).write_text(log_text[:5000], encoding="utf-8")
    return devices, duration


def best_os_match(host: ET.Element) -> dict:
    """Return the strongest structured Nmap OS match without overstating certainty.

    Nmap's accuracy is a fingerprint-match score, not a calibrated probability.
    OS classes and CPEs are retained as supporting evidence; no hardware model
    is inferred from an OS match.
    """
    matches = host.findall("./os/osmatch")
    if not matches:
        return {}
    def accuracy(node: ET.Element) -> int:
        try:
            return max(0, min(100, int(node.get("accuracy", "0"))))
        except (TypeError, ValueError):
            return 0
    best = max(matches, key=accuracy)
    classes = []
    for node in best.findall("./osclass"):
        classes.append({
            "vendor": (node.get("vendor") or "")[:100],
            "family": (node.get("osfamily") or "")[:100],
            "generation": (node.get("osgen") or "")[:60],
            "type": (node.get("type") or "")[:60],
            "accuracy": accuracy(node),
            "cpe": [
                (item.text or "")[:200]
                for item in node.findall("./cpe") if item.text
            ][:10],
        })
    return {
        "name": (best.get("name") or "")[:200],
        "accuracy": accuracy(best),
        "classes": classes[:20],
        "method": "Nmap OS fingerprint",
        "interpretation": "Nmap match accuracy; not a probability",
    }
