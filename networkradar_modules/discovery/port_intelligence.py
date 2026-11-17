"""Explicit, single-host full TCP port intelligence.

This scanner is opt-in and intentionally separate from routine discovery. It
never chooses targets: callers must supply the current authorised private
network and one currently known host. It performs TCP connect/service detection
only; no exploit scripts, credentials, UDP sweep or stealth options are used.
"""
from __future__ import annotations

import ipaddress
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Callable


def validate_target(target: str, network: str) -> str:
    """Return a canonical private IPv4 target inside the supplied network."""
    try:
        address = ipaddress.ip_address(str(target).strip())
        scope = ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError as exc:
        raise ValueError("A valid IPv4 target and authorised network are required.") from exc
    if address.version != 4 or scope.version != 4:
        raise ValueError("Full TCP intelligence supports IPv4 targets only.")
    if not address.is_private or not scope.is_private or address not in scope:
        raise ValueError("Target is outside the authorised private IPv4 network.")
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        raise ValueError("Target address is not eligible for a LAN scan.")
    return str(address)


def parse_full_tcp_xml(xml_text: str) -> dict:
    """Parse one Nmap XML host result without converting guesses into facts."""
    root = ET.fromstring(xml_text)
    hosts = root.findall("host")
    if not hosts:
        return {"host_state": "NO_RESULT", "completed": False, "open_ports": [],
                "open_count": 0, "services": []}
    host = hosts[0]
    status = host.find("status")
    host_state = status.get("state", "unknown") if status is not None else "unknown"
    ports_node = host.find("ports")
    services = []
    if ports_node is not None:
        for node in ports_node.findall("port"):
            state = node.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                number = int(node.get("portid", ""))
            except (TypeError, ValueError):
                continue
            if not 1 <= number <= 65535 or node.get("protocol") != "tcp":
                continue
            service = node.find("service")
            services.append({
                "port": number,
                "protocol": "tcp",
                "name": (service.get("name", "unknown") if service is not None else "unknown")[:80],
                "product": (service.get("product", "") if service is not None else "")[:120],
                "version": (service.get("version", "") if service is not None else "")[:80],
                "extrainfo": (service.get("extrainfo", "") if service is not None else "")[:120],
                "method": (service.get("method", "") if service is not None else "")[:30],
                "tunnel": (service.get("tunnel", "") if service is not None else "")[:30],
            })
    services.sort(key=lambda item: item["port"])
    return {
        "host_state": host_state,
        "completed": ports_node is not None and host_state == "up",
        "open_ports": [item["port"] for item in services],
        "open_count": len(services),
        "services": services,
    }


def run_full_tcp_scan(
    target: str,
    network: str,
    executable: str,
    *,
    timeout: float = 190,
    runner: Callable = subprocess.run,
) -> dict:
    """Probe all 65,535 TCP ports on one authorised private IPv4 endpoint."""
    ip = validate_target(target, network)
    budget = min(240.0, max(30.0, float(timeout)))
    command = [
        str(executable), "-sT", "-p-", "-sV", "--version-light",
        "--reason", "--max-retries", "1", "--max-rate", "200",
        "--host-timeout", f"{int(min(180, budget - 10))}s",
        "-n", "-oX", "-", ip,
    ]
    started = time.monotonic()
    try:
        result = runner(command, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=budget)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Full TCP scan exceeded its {int(budget)}-second budget. "
            "No complete result was recorded; run a targeted scan or retry later."
        ) from exc
    duration = round(time.monotonic() - started, 2)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()[-500:]
        raise RuntimeError(detail or f"Nmap exited with code {result.returncode}.")
    if not (result.stdout or "").strip():
        raise RuntimeError("Nmap returned no XML; scan completeness cannot be established.")
    parsed = parse_full_tcp_xml(result.stdout)
    if not parsed["completed"]:
        raise RuntimeError("Nmap did not return a completed, live-host TCP port table.")
    return {"ip": ip, **parsed, "duration_seconds": duration,
            "scan_method": "nmap-full-tcp", "ports_tested": 65535}
