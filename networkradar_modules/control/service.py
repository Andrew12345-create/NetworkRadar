"""In-memory coordinator for the NetworkRadar router-control adapters."""
from __future__ import annotations

import ipaddress
import threading

from .routeros import RouterOSAdapter, validate_router_host


class NetworkControlManager:
    """Keeps router credentials in memory and binds a session to one LAN."""

    def __init__(self, adapter_factory=RouterOSAdapter):
        self._factory = adapter_factory
        self._lock = threading.RLock()
        self._adapter = None
        self._network = ""
        self._host = ""

    def connect_routeros(self, host, username, password, port, ca_file, network):
        scope = ipaddress.ip_network(str(network), strict=False)
        if scope.version != 4 or not scope.is_private:
            raise ValueError("Router control requires an authorised private IPv4 network.")
        host = validate_router_host(host, str(scope))
        candidate = self._factory(host, username, password, port=port, ca_file=ca_file)
        info = candidate.connect()
        with self._lock:
            self._adapter = candidate
            self._network = str(scope)
            self._host = host
        return {
            "connected": True, "provider": "mikrotik-routeros",
            "host": host, "identity": info.get("identity", ""),
            "model": info.get("model", ""), "version": info.get("version", ""),
            "ipv6_supported": bool(info.get("ipv6_supported")),
            "fasttrack_detected": bool(info.get("fasttrack_detected")),
            "interface_lists": info.get("interface_lists", []),
            "credentials_persisted": False,
        }

    def disconnect(self):
        with self._lock:
            self._adapter = None
            self._network = ""
            self._host = ""
        return {"connected": False}

    def _require(self, network):
        with self._lock:
            adapter, stored_network = self._adapter, self._network
        if adapter is None:
            raise RuntimeError("Connect an authorised MikroTik RouterOS 7+ router first.")
        try:
            current = str(ipaddress.ip_network(str(network), strict=False))
        except ValueError as exc:
            raise PermissionError("Current network context is unavailable.") from exc
        if current != stored_network:
            raise PermissionError("The active network changed. Reconnect to the router on the currently authorised network.")
        if ipaddress.ip_address(self._host) not in ipaddress.ip_network(current):
            raise PermissionError("Router host is outside the current network scope.")
        return adapter

    def status(self, current_network=""):
        with self._lock:
            adapter, host, scope = self._adapter, self._host, self._network
        if adapter is None:
            return {
                "connected": False, "provider": "",
                "supported_providers": ["MikroTik RouterOS 7+ (HTTPS REST)"],
                "message": "No router is connected. Router control is inactive.",
            }
        try:
            current = str(ipaddress.ip_network(str(current_network), strict=False))
        except ValueError:
            current = ""
        if current != scope:
            return {
                "connected": False, "provider": "mikrotik-routeros",
                "host": host, "message": "Router session is suspended because the current network differs from the connected network. Reconnect after authorising the correct network.",
                "credentials_persisted": False,
            }
        return adapter.status()

    def set_bandwidth(self, network, ip, download_mbps, upload_mbps):
        return self._require(network).set_bandwidth_limit(ip, download_mbps, upload_mbps)

    def remove_bandwidth(self, network, ip):
        return self._require(network).remove_bandwidth_limit(ip)

    def pause_device(self, network, ip, ipv6_addresses, minutes, allow_ipv4_only=False):
        return self._require(network).pause_device(ip, ipv6_addresses, minutes, allow_ipv4_only)

    def pause_network(self, network, minutes, allow_ipv4_only=False):
        return self._require(network).pause_network(network, minutes, allow_ipv4_only)

    def resume_device(self, network, ip):
        return self._require(network).resume_device(ip)

    def resume_network(self, network):
        return self._require(network).resume_network()

    def restore_all(self, network):
        return self._require(network).restore_all()


NETWORK_CONTROL = NetworkControlManager()
