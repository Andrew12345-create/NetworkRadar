"""Pure network-interface and packet-capture adapter selection helpers."""
from __future__ import annotations

import ipaddress
import re


def _norm_mac(m):
    if not m:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", m).upper()
    return ":".join(clean[i:i+2] for i in range(0, 12, 2)) if len(clean) == 12 else ""

def _is_real_mac(m):
    if not m:
        return False
    clean = re.sub(r"[^0-9A-Fa-f]", "", m)
    return len(clean) == 12 and clean.upper() not in {"000000000000", "FFFFFFFFFFFF"}

def _select_primary_adapter(adapters, default_routes):
    """Choose the active interface with the lowest effective default-route metric."""
    routed = [item for item in adapters if item.get("idx") in default_routes]
    if routed:
        return min(
            routed,
            key=lambda item: int(default_routes[item["idx"]].get("_metric", 999999)),
        )
    return adapters[0] if adapters else None

def _select_ipv4_interface_rows(rows):
    """Choose one usable, preferred IPv4 address per Windows interface."""
    selected = {}
    priorities = {}
    for row in rows:
        try:
            idx = int(row["InterfaceIndex"])
            address = ipaddress.ip_address(str(row.get("IPAddress") or "").strip())
            if (address.version != 4 or address.is_loopback or address.is_link_local
                    or address.is_unspecified or address.is_multicast):
                continue
            state = str(row.get("AddressState") or "").casefold()
            skip_source = str(row.get("SkipAsSource", "False")).casefold() in {
                "true", "1", "yes"
            }
            priority = (1 if state == "preferred" else 0, 0 if skip_source else 1)
        except (KeyError, ValueError, TypeError):
            continue
        if idx not in priorities or priority > priorities[idx]:
            selected[idx] = row
            priorities[idx] = priority
    return selected

def _select_tshark_interface(interfaces, *, preferred="", primary_guid="",
                             primary_name="", primary_description=""):
    """Prefer the exact active Windows adapter, not the first Wi-Fi-looking device."""
    if preferred:
        pref = str(preferred).strip().strip('"')
        for idx, desc in interfaces:
            if pref.casefold() == str(idx).casefold() or pref.casefold() in str(desc).casefold():
                return str(idx)
        if pref.startswith(r"\Device\NPF_"):
            return pref
        raise RuntimeError(
            "Configured NETWORKRADAR_TSHARK_INTERFACE was not found by TShark -D: "
            + pref[:160]
        )

    guid_raw = str(primary_guid or "").strip().strip("{}").replace("-", "").casefold()
    guid = guid_raw if re.fullmatch(r"[0-9a-f]{32}", guid_raw) else ""
    if guid:
        for idx, desc in interfaces:
            desc_guid = re.sub(r"[^0-9a-f]", "", str(desc).casefold())
            if guid in desc_guid:
                return str(idx)

    names = [
        str(x).strip().casefold()
        for x in (primary_name, primary_description)
        if str(x or "").strip()
        and str(x).strip().casefold() not in {"manual override", "no active adapter"}
    ]
    for name in names:
        for idx, desc in interfaces:
            if name in str(desc).casefold():
                return str(idx)

    if names:
        raise RuntimeError(
            "The active Windows network adapter was not found in TShark -D. "
            "Set NETWORKRADAR_TSHARK_INTERFACE to the correct TShark interface; "
            "NetworkRadar will not silently capture another adapter."
        )

    wifi = [(idx, desc) for idx, desc in interfaces
            if re.search(r"\b(wi[ -]?fi|wireless|802\.11)\b", desc, re.IGNORECASE)
            and not re.search(r"loopback|virtualbox|vmware", desc, re.IGNORECASE)]
    if wifi:
        return str(wifi[0][0])
    ethernet = [(idx, desc) for idx, desc in interfaces
                if re.search(r"\bethernet\b", desc, re.IGNORECASE)
                and not re.search(r"loopback|virtualbox|vmware", desc, re.IGNORECASE)]
    if ethernet:
        return str(ethernet[0][0])
    physical = [(idx, desc) for idx, desc in interfaces
                if not re.search(r"loopback|virtualbox|vmware|bluetooth|npcap loopback", desc, re.IGNORECASE)]
    if physical:
        return str(physical[0][0])
    raise RuntimeError(
        "No usable TShark interface found. Check Npcap and set NETWORKRADAR_TSHARK_INTERFACE."
    )

