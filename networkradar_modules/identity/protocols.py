"""Safe parsers for passive SSDP and mDNS/DNS-SD identity observations.

These helpers only interpret already-captured local-network observations.
They never fetch a device-advertised URL, probe a target, or treat a service
advertisement as proof of hardware identity.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

_MAX_MESSAGE = 16_384
_MAX_HEADER_VALUE = 1_024
_MAX_RECORDS = 256
_SERVICE_HINTS = {
    "_airplay._tcp": ("media receiver / AirPlay-capable device", 62),
    "_raop._tcp": ("audio receiver / AirPlay audio", 58),
    "_googlecast._tcp": ("Google Cast-capable device", 62),
    "_printer._tcp": ("network printer candidate", 58),
    "_ipp._tcp": ("IPP printer candidate", 64),
    "_ipps._tcp": ("secure IPP printer candidate", 64),
    "_scanner._tcp": ("network scanner candidate", 62),
    "_smb._tcp": ("SMB file-sharing service", 45),
    "_ssh._tcp": ("SSH service", 35),
    "_http._tcp": ("HTTP service", 25),
    "_https._tcp": ("HTTPS service", 25),
    "_hap._tcp": ("HomeKit-compatible service", 58),
    "_matter._tcp": ("Matter commissioning/service", 55),
}


def _clean(value: Any, limit: int = _MAX_HEADER_VALUE) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", "", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def parse_ssdp_message(message: Any) -> dict[str, Any]:
    """Parse an SSDP response/NOTIFY header block without dereferencing LOCATION."""
    raw = str(message or "")
    if len(raw) > _MAX_MESSAGE:
        raw = raw[:_MAX_MESSAGE]
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start = _clean(lines[0] if lines else "", 256)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        name = _clean(key, 64).casefold()
        if not name or name in headers:
            continue
        headers[name] = _clean(value)
    usn = headers.get("usn", "")
    uuid_match = re.search(r"uuid:([^:]+)", usn, re.IGNORECASE)
    server = headers.get("server", "")
    st = headers.get("st", "") or headers.get("nt", "")
    return {
        "protocol": "SSDP",
        "message_type": "NOTIFY" if start.upper().startswith("NOTIFY ") else
                        "RESPONSE" if start.upper().startswith("HTTP/") else "OTHER",
        "status_line": start,
        "usn": usn,
        "uuid": _clean(uuid_match.group(1), 128) if uuid_match else "",
        "target": st,
        "server": server,
        "location": headers.get("location", ""),
        "manufacturer_hint": "",
        "model_hint": "",
        "headers": headers,
        "limitations": [
            "SSDP headers are self-advertised and may be absent, generic or spoofed.",
            "LOCATION is retained as evidence only; this parser never fetches it.",
            "A UPnP service type is not proof of the physical device model.",
        ],
    }


def analyse_mdns_services(records: Any) -> dict[str, Any]:
    """Interpret captured DNS-SD service records supplied as mappings."""
    if not isinstance(records, (list, tuple)):
        records = []
    services = []
    hints = []
    seen = set()
    for record in list(records)[:_MAX_RECORDS]:
        if not isinstance(record, Mapping):
            continue
        name = _clean(record.get("name") or record.get("service") or "", 255)
        service_type = name.casefold()
        matched = next((item for item in _SERVICE_HINTS if item in service_type), "")
        port = record.get("port")
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        if port is not None and not 1 <= port <= 65535:
            port = None
        target = _clean(record.get("target") or record.get("hostname") or "", 255)
        key = (service_type, target.casefold(), port)
        if not name or key in seen:
            continue
        seen.add(key)
        item = {"name": name, "target": target, "port": port,
                "service_class": matched or "unclassified service"}
        services.append(item)
        if matched:
            category, confidence = _SERVICE_HINTS[matched]
            hints.append({
                "category": category,
                "confidence": confidence,
                "attribute": "service_capability",
                "source": "mDNS/DNS-SD",
                "reason": f"Observed DNS-SD service advertisement {name}",
            })
    return {
        "protocol": "mDNS/DNS-SD",
        "services": services,
        "hints": hints,
        "record_count": len(services),
        "limitations": [
            "DNS-SD advertisements describe services, not necessarily the host hardware.",
            "Service names and TXT metadata are client-controlled and may be spoofed.",
            "Absence of an advertisement does not mean the device lacks that capability.",
        ],
    }
