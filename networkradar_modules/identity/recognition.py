"""Evidence-family compatibility rules for device-category recognition."""
from __future__ import annotations

_RULE_FAMILIES = {
    "service": frozenset({"service", "mdns", "upnp", "snmp"}),
    "product": frozenset({"product", "snmp", "upnp", "mdns"}),
    "os": frozenset({"os", "tcpip"}),
    "reported": frozenset({"reported", "mdns", "upnp"}),
    "dhcp": frozenset({"dhcp"}),
}


def recognition_family_compatible(rule_family: str, evidence_family: str) -> bool:
    """Prevent weak/context-only evidence (notably MAC registrants) from
    satisfying product, OS or device-role signatures.
    """
    rule = str(rule_family or "").strip().casefold()
    evidence = str(evidence_family or "").strip().casefold()
    if not rule or not evidence:
        return False
    allowed = _RULE_FAMILIES.get(rule)
    if allowed is None:
        return rule in {"any", "*"} and evidence != "oui"
    return evidence in allowed
