"""IEEE MAC address-block registry parsing and conservative lookup.

MA-L, MA-M and MA-S prefixes have different lengths. The registry assignee
is not necessarily the device manufacturer: addresses can belong to an OEM,
ODM, module supplier, virtual interface or privacy-randomised address.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Mapping

_HEX = re.compile(r"^[0-9A-F]{12}$")
_VALID_LENGTHS = {6: "MA-L", 7: "MA-M", 9: "MA-S"}


def normalise_mac_hex(value: Any) -> str:
    """Return twelve uppercase hex digits from a valid 48-bit MAC."""
    raw = str(value or "").strip()
    if not raw or not re.fullmatch(r"[0-9A-Fa-f:.\-\s]+", raw):
        return ""
    raw = re.sub(r"[:.\-\s]", "", raw).upper()
    return raw if _HEX.fullmatch(raw) else ""


def _clean_prefix(value: Any) -> str:
    prefix = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return prefix if len(prefix) in _VALID_LENGTHS else ""


def parse_ieee_registry(raw: str, registry: str) -> dict[str, dict[str, str]]:
    """Parse IEEE public-listing CSV or legacy text into prefix metadata."""
    registry = str(registry or "").strip().upper()
    if registry not in {"MA-L", "MA-M", "MA-S"}:
        raise ValueError("registry must be MA-L, MA-M or MA-S")
    text = str(raw or "").lstrip("\ufeff")
    parsed: dict[str, dict[str, str]] = {}

    # IEEE CSV public listings use an Assignment and Organization Name column.
    try:
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames:
            headers = {str(h).strip().casefold(): h for h in reader.fieldnames}
            assignment_key = next((headers[k] for k in ("assignment", "oui", "oui-36", "mac address") if k in headers), None)
            org_key = next((headers[k] for k in ("organization name", "organization", "company", "assignee") if k in headers), None)
            if assignment_key and org_key:
                for row in reader:
                    prefix = _clean_prefix(row.get(assignment_key))
                    organization = str(row.get(org_key) or "").strip()
                    if prefix and len(prefix) == { "MA-L": 6, "MA-M": 7, "MA-S": 9 }[registry] and organization:
                        parsed[prefix] = {
                            "organization": organization[:180],
                            "registry": registry,
                        }
                if parsed:
                    return parsed
    except (csv.Error, UnicodeError):
        pass

    # Legacy IEEE text format, e.g. A0-B1-C2 (hex) Example, Inc.
    expected = {"MA-L": 6, "MA-M": 7, "MA-S": 9}[registry]
    for line in text.splitlines():
        match = re.match(
            r"^\s*([0-9A-Fa-f-]{6,11})\s+\((?:hex|MA-L|MA-M|MA-S)\)\s+(.+?)\s*$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        prefix = _clean_prefix(match.group(1))
        organization = match.group(2).strip()
        if prefix and len(prefix) == expected and organization:
            parsed[prefix] = {
                "organization": organization[:180],
                "registry": registry,
            }
    return parsed


def lookup_ieee_assignment(mac: Any, assignments: Mapping[str, Any]) -> dict[str, Any]:
    """Find the most-specific global unicast MA-L/MA-M/MA-S assignment."""
    normalised = normalise_mac_hex(mac)
    if not normalised:
        return {}
    first_octet = int(normalised[:2], 16)
    if first_octet & 0x01 or first_octet & 0x02:
        return {}
    for length in (9, 7, 6):
        prefix = normalised[:length]
        value = assignments.get(prefix)
        if not value:
            continue
        if isinstance(value, Mapping):
            organization = str(value.get("organization") or "").strip()
            registry = str(value.get("registry") or _VALID_LENGTHS[length]).upper()
            if registry not in _VALID_LENGTHS.values() or len(prefix) != {"MA-L": 6, "MA-M": 7, "MA-S": 9}[registry]:
                registry = _VALID_LENGTHS[length]
        else:
            organization = str(value).strip()
            registry = _VALID_LENGTHS[length]
        if not organization:
            continue
        return {
            "prefix": prefix,
            "registry": registry,
            "prefix_bits": length * 4,
            "organization": organization,
            "assignment_type": {
                "MA-L": "large MAC address block (OUI)",
                "MA-M": "medium MAC address block",
                "MA-S": "small MAC address block (OUI-36)",
            }[registry],
            "interpretation": "IEEE address-block registrant; not proof of device manufacturer",
        }
    return {}
