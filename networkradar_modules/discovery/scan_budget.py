"""Adaptive wall-clock budgets for bounded, authorised deep discovery."""
from __future__ import annotations


def deep_scan_profile(device_count: int, configured_top_ports: int = 100) -> dict[str, int]:
    """Return a predictable scan budget that scales down for larger inventories.

    These are upper bounds, not promises about actual scan duration. Nmap's
    per-host timeout limits slow targets; subprocess timeouts bound the whole
    pass. The fallback retains useful service evidence when the full pass is
    slow or unavailable.
    """
    count = max(0, int(device_count))
    configured = max(1, min(1000, int(configured_top_ports)))
    if count <= 8:
        ports, tcp_timeout, host_timeout = 100, 75, 25
        fallback_ports, fallback_timeout, fallback_host = 50, 35, 15
        udp_timeout, udp_host = 30, 12
    elif count <= 32:
        ports, tcp_timeout, host_timeout = 75, 70, 20
        fallback_ports, fallback_timeout, fallback_host = 35, 35, 12
        udp_timeout, udp_host = 30, 10
    elif count <= 128:
        ports, tcp_timeout, host_timeout = 50, 60, 15
        fallback_ports, fallback_timeout, fallback_host = 25, 30, 10
        udp_timeout, udp_host = 25, 8
    else:
        ports, tcp_timeout, host_timeout = 25, 45, 12
        fallback_ports, fallback_timeout, fallback_host = 15, 25, 8
        udp_timeout, udp_host = 20, 6
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
