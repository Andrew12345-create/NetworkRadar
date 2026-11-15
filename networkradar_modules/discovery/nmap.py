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
    command: Sequence[str] = (
        str(executable), "-sn", "-R", "-oX", "-", str(network)
    )
    started = time.time()
    result = runner(
        list(command),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    duration = round(time.time() - started, 2)
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    Path(log_path).write_text(
        stderr + "\n" + stdout[:2000],
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed: {stderr[-1000:]}")
    return parse_nmap_xml(stdout), duration


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
