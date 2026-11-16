"""Bounded, read-only TCP connect discovery for an explicitly authorised LAN.

This supplements ARP/ICMP host discovery: a host that ignores ping/ARP probes
may still reveal itself by accepting a TCP connection on a common service port.
No credentials, exploit payloads, UDP floods, or port-range brute force are used.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

DEFAULT_PORTS = (
    22, 23, 53, 80, 135, 139, 443, 445, 554, 631, 9100, 3389,
    5000, 8008, 8080, 8443,
)


def _probe_one(target: tuple[str, int], *, connector: Callable, timeout: float):
    ip, port = target
    sock = None
    try:
        sock = connector((ip, port), timeout=timeout)
        return ip, port, True
    except (OSError, TimeoutError, socket.timeout):
        return ip, port, False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def sweep_tcp_hosts(
    network: str,
    *,
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout: float = 0.35,
    max_workers: int = 128,
    max_hosts: int = 512,
    connector: Callable = socket.create_connection,
    progress: Callable | None = None,
) -> dict:
    """Discover TCP-responsive hosts inside a private IPv4 subnet.

    The address-space and concurrency limits are deliberate safety controls.
    A successful TCP handshake is evidence of reachability, not device identity.
    """
    started = time.monotonic()
    try:
        scope = ipaddress.ip_network(str(network), strict=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("A valid IPv4 network scope is required.") from exc
    if scope.version != 4 or not scope.is_private:
        raise ValueError("TCP discovery is restricted to private IPv4 networks.")
    targets = [str(ip) for ip in scope.hosts()]
    if len(targets) > int(max_hosts):
        raise ValueError(
            f"Network contains {len(targets)} addresses; bounded TCP discovery "
            f"is limited to {int(max_hosts)} hosts per pass."
        )
    selected_ports = sorted({
        int(port) for port in ports
        if isinstance(port, int) and 1 <= port <= 65535
    })
    if not selected_ports:
        raise ValueError("At least one valid TCP service port is required.")
    if not 0.05 <= float(timeout) <= 2.0:
        raise ValueError("TCP probe timeout must be between 0.05 and 2 seconds.")
    workers = max(1, min(int(max_workers), 128))
    work = [(ip, port) for ip in targets for port in selected_ports]
    open_by_ip: dict[str, list[int]] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nr-tcp") as pool:
        futures = [
            pool.submit(_probe_one, item, connector=connector, timeout=float(timeout))
            for item in work
        ]
        for future in as_completed(futures):
            ip, port, is_open = future.result()
            completed += 1
            if is_open:
                open_by_ip.setdefault(ip, []).append(port)
            if progress and (completed == len(work) or completed % 64 == 0):
                progress(completed, len(work), len(open_by_ip))
    devices = []
    for ip, found_ports in sorted(open_by_ip.items(), key=lambda row: ipaddress.ip_address(row[0])):
        found_ports = sorted(set(found_ports))
        devices.append({
            "ip": ip,
            "mac": "Unavailable",
            "vendor": "Unknown",
            "hostname": "-",
            "device_name": "",
            "friendly_name": "",
            "device_type": "Unclassified device",
            "os_guess": "Unknown",
            "model": "",
            "identification_confidence": 0,
            "identification_methods": "",
            "port_numbers": found_ports,
            "open_ports": ", ".join(map(str, found_ports)),
            "service_summary": "",
            "services_found": [],
            "discovery_method": "Bounded TCP connect discovery",
            "discovery_reason": "One or more common TCP service ports accepted a connection.",
            "discovery_sources": ["TCP connect"],
            "tcp_probe_evidence": {
                "method": "TCP connect",
                "open_ports": found_ports,
                "tested_ports": selected_ports,
                "interpretation": "Reachability evidence only; not a device identity claim.",
            },
        })
    elapsed = round(time.monotonic() - started, 2)
    return {
        "status": "COMPLETE",
        "network": str(scope),
        "targets": len(targets),
        "ports_per_host": len(selected_ports),
        "probes": len(work),
        "responders": len(devices),
        "open_port_observations": sum(len(row["port_numbers"]) for row in devices),
        "duration_seconds": elapsed,
        "devices": devices,
        "limitations": (
            "Only hosts accepting TCP connections on the selected ports are found. "
            "Sleeping devices, filtered services, client isolation and VLAN boundaries "
            "remain invisible to this local vantage point."
        ),
    }
