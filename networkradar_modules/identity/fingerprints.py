"""Pure device identity and network-fingerprint primitives.

These helpers deliberately avoid database, network and application-global
dependencies so their behaviour can be tested independently.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any, Mapping


_MAC_RE = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}")


def normalise_mac(mac: Any) -> str:
    """Return a canonical uppercase colon-delimited MAC, or an empty string."""
    value = str(mac or "").strip().replace("-", ":").upper()
    return value if _MAC_RE.fullmatch(value) else ""


def mac_properties(mac: Any) -> dict[str, Any]:
    """Describe IEEE address bits without assuming the OUI identifies a device."""
    value = normalise_mac(mac)
    if not value:
        return {
            "valid": False,
            "multicast": False,
            "locally_administered": False,
            "unicast": False,
            "prefix": "",
        }
    first = int(value[:2], 16)
    multicast = bool(first & 0x01)
    locally_administered = bool(first & 0x02)
    return {
        "valid": True,
        "multicast": multicast,
        "locally_administered": locally_administered,
        "unicast": not multicast,
        "prefix": value[:8].replace(":", ""),
    }


def derive_identity(device: Mapping[str, Any]) -> tuple[str, str, str]:
    """Derive a stable identity key; randomised MACs remain IP-scoped."""
    ip = str(device.get("ip") or "").strip()
    if not ip:
        raise ValueError("device must contain a non-empty IP address")
    mac = normalise_mac(device.get("mac"))
    if mac:
        first = int(mac[:2], 16)
        if not (first & 0x02):
            key = f"mac:{mac}"
            basis = "MAC"
        else:
            key = f"ip:{ip}"
            basis = "IP fallback (locally administered MAC ignored)"
    else:
        key = f"ip:{ip}"
        basis = "IP fallback"
    derived_id = uuid.uuid5(uuid.NAMESPACE_URL, "nr:" + key).hex[:24]
    return derived_id, key, basis


def dhcp_fingerprint(vendor_class: Any, parameter_request_list: Any) -> str:
    """Hash normalised DHCP vendor-class and parameter-request-list values."""
    vendor = re.sub(r"\s+", " ", str(vendor_class or "").strip().lower())[:120]
    raw_prl = str(parameter_request_list or "")
    prl = ",".join(part.strip() for part in raw_prl.split(",") if part.strip())
    return hashlib.sha256((vendor + "|" + prl).encode("utf-8", "ignore")).hexdigest()[:24]
