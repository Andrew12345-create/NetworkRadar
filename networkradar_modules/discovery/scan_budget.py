"""Adaptive wall-clock budgets for bounded, authorised deep discovery.

Budgets are deliberately conservative: the caller supplies only the targets
selected by the adaptive fingerprint planner. Per-host and whole-process
limits remain independent so a filtered endpoint cannot hold the scan open.
"""
from __future__ import annotations


def deep_scan_profile(device_count: int, configured_top_ports: int = 100) -> dict[str, int]:
    """Return hard upper bounds scaled to the selected target count."""
    count = max(0, int(device_count))
    configured = max(1, min(1000, int(configured_top_ports)))
    if count <= 4:
        ports, tcp_timeout, host_timeout = 50, 45, 15
        fallback_ports, fallback_timeout, fallback_host = 25, 25, 10
        udp_timeout, udp_host = 12, 6
    elif count <= 8:
        ports, tcp_timeout, host_timeout = 50, 50, 15
        fallback_ports, fallback_timeout, fallback_host = 25, 25, 10
        udp_timeout, udp_host = 12, 6
    elif count <= 16:
        ports, tcp_timeout, host_timeout = 40, 50, 12
        fallback_ports, fallback_timeout, fallback_host = 20, 25, 8
        udp_timeout, udp_host = 12, 6
    elif count <= 32:
        ports, tcp_timeout, host_timeout = 35, 45, 10
        fallback_ports, fallback_timeout, fallback_host = 20, 25, 8
        udp_timeout, udp_host = 10, 5
    elif count <= 128:
        ports, tcp_timeout, host_timeout = 25, 35, 8
        fallback_ports, fallback_timeout, fallback_host = 15, 20, 6
        udp_timeout, udp_host = 8, 4
    else:
        ports, tcp_timeout, host_timeout = 15, 25, 6
        fallback_ports, fallback_timeout, fallback_host = 10, 15, 5
        udp_timeout, udp_host = 6, 3
    return {
        "tcp_top_ports": min(configured, ports),
        "tcp_timeout": tcp_timeout,
        "tcp_host_timeout": host_timeout,
        "tcp_fallback_top_ports": min(configured, fallback_ports),
        "tcp_fallback_timeout": fallback_timeout,
        "tcp_fallback_host_timeout": fallback_host,
        "udp_timeout": udp_timeout,
        "udp_host_timeout": udp_host,
    }
