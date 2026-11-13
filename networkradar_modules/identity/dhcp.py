"""Conservative DHCP client fingerprint interpretation.

DHCP option 60 (vendor class), option 55 (parameter request list), hostname
and client identifier are useful fingerprints, but are not unique hardware
identifiers. This module returns explainable hints and never claims an exact
device model from DHCP alone.
"""
from __future__ import annotations

import re
from typing import Any

_OPTION_NAMES = {
    1: "subnet_mask", 2: "time_offset", 3: "router", 6: "dns",
    12: "hostname", 15: "domain_name", 26: "interface_mtu",
    28: "broadcast", 31: "router_discovery", 33: "static_routes",
    43: "vendor_specific", 44: "netbios_name_server",
    46: "netbios_node_type", 47: "netbios_scope",
    51: "lease_time", 54: "dhcp_server", 55: "parameter_request_list",
    58: "renewal_time", 59: "rebinding_time", 60: "vendor_class",
    61: "client_identifier", 66: "tftp_server", 67: "bootfile",
    77: "user_class", 81: "client_fqdn", 93: "client_architecture",
    94: "client_network_interface", 97: "client_machine_identifier",
    119: "domain_search", 121: "classless_static_routes",
    125: "vendor_identifying_information", 252: "proxy_autodiscovery",
}
def parse_parameter_request_list(value: Any) -> list[int]:
    """Parse a TShark-rendered option 55 list without accepting arbitrary ints."""
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    values: list[int] = []
    for token in re.split(r"[,;\s]+", text):
        token = token.strip()
        if not token:
            continue
        if token.lower().startswith("0x"):
            if not re.fullmatch(r"0x[0-9a-fA-F]{1,2}", token):
                continue
            number = int(token[2:], 16)
        else:
            if not re.fullmatch(r"[0-9]{1,3}", token):
                continue
            number = int(token, 10)
        if 0 <= number <= 254 and number not in values:
            values.append(number)
    return values[:128]


def _normalise_text(value: Any, limit: int = 160) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())[:limit]


def analyse_dhcp_identity(
    vendor_class: Any = "",
    hostname: Any = "",
    parameter_request_list: Any = "",
    client_identifier: Any = "",
) -> dict[str, Any]:
    """Return cautious family/role hints and a readable DHCP fingerprint."""
    vendor = _normalise_text(vendor_class).casefold()
    host = _normalise_text(hostname).casefold()
    client_id = _normalise_text(client_identifier)
    options = parse_parameter_request_list(parameter_request_list)
    option_set = set(options)
    hints: list[dict[str, Any]] = []

    def hint(category: str, confidence: int, reason: str, attribute: str = "client_family"):
        item = {"category": category, "confidence": confidence,
                "reason": reason, "attribute": attribute,
                "source": "DHCP option 60 / option 12"}
        if item not in hints:
            hints.append(item)

    # Stronger explicit vendor-class identifiers. Confidence is a heuristic,
    # not a probability, and is intentionally capped below exact identity.
    if re.search(r"\bandroid[-_ ]dhcp(?:[-_ ]|\b)", vendor):
        hint("Android mobile client", 78, "Explicit Android DHCP vendor-class token")
    if re.search(r"\bmsft\s*\d", vendor):
        hint("Microsoft DHCP client", 70, "Microsoft vendor-class identifier; Windows family is likely but not proven")
    if re.search(r"\b(udhcp|busybox)\b", vendor):
        hint("Embedded Linux DHCP client", 72, "BusyBox/udhcp vendor-class identifier")
    if re.search(r"\bdhcpcd(?:[-/ ]|\b)", vendor):
        hint("dhcpcd-based client", 62, "dhcpcd client identifier; used by multiple Unix-like systems")
    if re.search(r"\b(px eclient|pxeclient)\b", vendor) or vendor.startswith("pxeclient"):
        hint("PXE network-boot client", 88, "PXEClient vendor-class identifier", "network_role")
    if re.search(r"\bipxe\b", vendor):
        hint("iPXE network-boot client", 92, "iPXE vendor-class identifier", "network_role")
    if re.search(r"\bhttpclient\b", vendor):
        hint("HTTP network-boot client", 82, "HTTPClient vendor-class identifier", "network_role")

    # Hostnames are client-supplied and therefore useful but lower trust.
    if re.search(r"\b(android|galaxy|pixel|iphone|ipad)\b", host):
        hint("Mobile device candidate", 56, "Client-supplied hostname contains a mobile-device token")
    if re.search(r"\b(printer|laserjet|deskjet|epson|brother|canon)\b", host):
        hint("Printer candidate", 62, "Client-supplied hostname contains a printer token")
    if re.search(r"\b(ap|access.?point|switch|router|gateway)\b", host):
        hint("Network infrastructure candidate", 55, "Client-supplied hostname contains an infrastructure token")

    # Option 93 is sometimes rendered into option 60/other metadata by capture
    # tools; this function only decodes it when a caller supplies an explicit
    # architecture list in future-compatible metadata. Do not guess it here.
    option_names = [_OPTION_NAMES.get(number, f"option_{number}") for number in options]
    features = []
    if 93 in option_set:
        features.append("Option 93 appears in the parameter-request list")
    if 97 in option_set:
        features.append("Option 97 appears in the parameter-request list")
    if 60 in option_set:
        features.append("Vendor class option requested")
    if 77 in option_set:
        features.append("User class option requested")
    if 119 in option_set:
        features.append("Domain search option requested")
    if 121 in option_set:
        features.append("Classless static route option requested")
    if 252 in option_set:
        features.append("Proxy auto-discovery option requested")

    # A PRL profile is retained as an observable signature only. It is not
    # converted into a Windows/Linux assertion because common clients overlap.
    prl_profile = " ".join(str(x) for x in options)
    fingerprint = {
        "vendor_class": _normalise_text(vendor_class),
        "hostname": _normalise_text(hostname),
        "parameter_request_list": options,
        "parameter_request_list_names": option_names,
        "client_identifier_present": bool(client_id),
        "prl_profile": prl_profile,
    }
    return {
        "hints": hints,
        "features": features,
        "fingerprint": fingerprint,
        "confidence_ceiling": 92 if any(h["attribute"] == "network_role" for h in hints) else 78,
        "limitations": [
            "DHCP values are client-supplied and can be changed or spoofed.",
            "Parameter-request-list patterns overlap across operating systems.",
            "DHCP alone cannot establish an exact manufacturer, model or serial number.",
        ],
    }
