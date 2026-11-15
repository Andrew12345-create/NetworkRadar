"""Stable, additive network workspace persistence helpers.

A workspace is keyed by an opaque ID. Fingerprints are immutable observations
linked to a workspace; IP subnets are deliberately not used as primary keys.
"""
from __future__ import annotations
import uuid

def classify_interface_type(name="", description="", media_type=""):
    text = " ".join(str(x or "") for x in (name, description, media_type)).lower()
    if any(t in text for t in ("vpn", "wireguard", "openvpn", "tunnel", "tap-windows", "wintun")):
        return "VPN"
    if any(t in text for t in ("wi-fi", "wifi", "wireless", "802.11")):
        return "WIFI"
    if any(t in text for t in ("virtual", "hyper-v", "vmware", "virtualbox", "loopback", "vethernet")):
        return "VIRTUAL"
    if "ethernet" in text or "802.3" in text:
        return "ETHERNET"
    return "OTHER"

def parse_netsh_wlan_interfaces(output):
    """Parse netsh WLAN output into interface-specific SSID/BSSID rows."""
    rows, current = [], None
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "name":
            if current:
                rows.append(current)
            current = {"name": value, "ssid": "", "bssid": ""}
        elif current is not None and key == "ssid" and not current["ssid"]:
            current["ssid"] = value
        elif current is not None and key == "bssid" and not current["bssid"]:
            current["bssid"] = value
    if current:
        rows.append(current)
    return rows

def ensure_workspace(conn, detected, timestamp):
    """Return/create workspace ID for an exact fingerprint; never inherit approval."""
    fingerprint = str(detected.get("fingerprint") or "").strip()
    if not fingerprint:
        return ""
    row = conn.execute(
        "SELECT network_id FROM network_fingerprint_history WHERE fingerprint=?",
        (fingerprint,),
    ).fetchone()
    if row:
        network_id = row[0]
        conn.execute(
            "UPDATE network_workspaces SET last_seen=?, current_fingerprint=?, status='SEEN' WHERE network_id=?",
            (timestamp, fingerprint, network_id),
        )
        conn.execute(
            "UPDATE network_fingerprint_history SET last_seen=? WHERE fingerprint=?",
            (timestamp, fingerprint),
        )
        return network_id
    network_id = uuid.uuid4().hex
    label = detected.get("ssid") or detected.get("network") or detected.get("interface") or "Discovered network"
    conn.execute(
        "INSERT INTO network_workspaces(network_id,display_name,network_type,created_at,last_seen,current_fingerprint,status) VALUES(?,?,?,?,?,?,?)",
        (network_id, str(label)[:120], str(detected.get("interface_type") or "OTHER"),
         timestamp, timestamp, fingerprint, "SEEN"),
    )
    conn.execute(
        "INSERT INTO network_fingerprint_history(fingerprint,network_id,first_seen,last_seen,network,gateway,gateway_mac,dns_servers,ssid,bssid,interface_name,interface_guid,confidence,fingerprint_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (fingerprint, network_id, timestamp, timestamp, str(detected.get("network") or ""),
         str(detected.get("gateway") or ""), str(detected.get("gateway_mac") or ""),
         str(detected.get("dns_servers") or ""), str(detected.get("ssid") or ""),
         str(detected.get("bssid") or ""), str(detected.get("interface") or ""),
         str(detected.get("interface_guid") or ""), int(detected.get("confidence") or 0),
         str(detected.get("fingerprint_raw") or "")),
    )
    return network_id

def record_interface_observation(conn, network_id, interface, timestamp, is_primary=False):
    if not network_id or not isinstance(interface, dict):
        return
    conn.execute(
        "INSERT INTO network_interface_observations(network_id,timestamp,interface_index,interface_name,interface_guid,interface_description,interface_type,status,ip,prefix,network,gateway,gateway_mac,dns_servers,dhcp,ssid,bssid,route_metric,adapter_mac,is_primary) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (network_id, timestamp, int(interface.get("idx") or interface.get("interface_index") or 0),
         str(interface.get("interface") or ""), str(interface.get("interface_guid") or ""),
         str(interface.get("interface_description") or ""), str(interface.get("interface_type") or "OTHER"),
         str(interface.get("status") or ""), str(interface.get("ip") or ""), interface.get("prefix"),
         str(interface.get("network") or ""), str(interface.get("gateway") or ""),
         str(interface.get("gateway_mac") or ""), str(interface.get("dns_servers") or ""),
         str(interface.get("dhcp") or ""), str(interface.get("ssid") or ""),
         str(interface.get("bssid") or ""), int(interface.get("route_metric") or 0),
         str(interface.get("adapter_mac") or ""), 1 if is_primary else 0),
    )

def upsert_legacy_network_profile(conn, detected, timestamp):
    """Keep the legacy subnet-keyed row, but never carry approval to a new fingerprint."""
    conn.execute(
        "INSERT INTO network_profiles(network,first_seen,last_seen,interface,gateway,ssid,approved,fingerprint,gateway_mac,adapter_mac,dns_servers,bssid,confidence) "
        "VALUES(?,?,?,?,?,?,0,?,?,?,?,?,?) "
        "ON CONFLICT(network) DO UPDATE SET "
        "approved=CASE WHEN network_profiles.fingerprint=excluded.fingerprint THEN network_profiles.approved ELSE 0 END, "
        "last_authorized=CASE WHEN network_profiles.fingerprint=excluded.fingerprint THEN network_profiles.last_authorized ELSE '' END, "
        "last_seen=excluded.last_seen,interface=excluded.interface,gateway=excluded.gateway,ssid=excluded.ssid, "
        "fingerprint=excluded.fingerprint,gateway_mac=excluded.gateway_mac,adapter_mac=excluded.adapter_mac, "
        "dns_servers=excluded.dns_servers,bssid=excluded.bssid,confidence=excluded.confidence",
        (str(detected.get("network") or ""), timestamp, timestamp,
         str(detected.get("interface") or ""), str(detected.get("gateway") or ""),
         str(detected.get("ssid") or ""), str(detected.get("fingerprint") or ""),
         str(detected.get("gateway_mac") or ""), str(detected.get("adapter_mac") or ""),
         str(detected.get("dns_servers") or ""), str(detected.get("bssid") or ""),
         int(detected.get("confidence") or 0)),
    )

def has_strong_network_anchor(detected):
    """Require a gateway MAC or BSSID before a fingerprint can authorise active discovery."""
    import json
    raw = detected.get("fingerprint_raw") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return False
    if not isinstance(raw, dict):
        return False
    return bool(raw.get("gateway_mac") or raw.get("bssid"))
