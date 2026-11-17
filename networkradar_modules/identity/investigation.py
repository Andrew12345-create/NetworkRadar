"""Evidence-aware next-step guidance for unidentified network devices.

This module never probes a device. It translates missing evidence into
operator guidance and keeps active actions conditional on network approval.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from .evidence_intelligence import plan_investigation_methods


def _present(value: Any) -> bool:
    text = str(value or "").strip().casefold()
    return text not in {
        "", "-", "unknown", "unavailable", "none", "n/a",
        "not observed", "not yet fingerprinted",
        "unclassified", "unclassified network device",
    } and not text.startswith(("unidentified device", "unknown device"))


def build_identity_next_steps(
    device: Mapping[str, Any] | None,
    evidence_sources: Iterable[str] | None = None,
    *,
    dhcp_observed: bool = False,
    mdns_observed: bool = False,
    ssdp_observed: bool = False,
    authorised: bool = False,
) -> dict[str, Any]:
    """Explain evidence gaps and rank safe next actions for one device."""
    device = device or {}
    sources = sorted({
        str(source or "").strip()
        for source in (evidence_sources or [])
        if str(source or "").strip()
    })
    source_text = " ".join(sources).casefold()
    ports = device.get("port_numbers") or device.get("open_ports") or []
    if isinstance(ports, str):
        ports_text = ports.strip()
    else:
        ports_text = ",".join(str(x) for x in ports)
    has_nmap = any(token in source_text for token in ("nmap", "tcp fingerprint", "service"))
    has_dhcp = dhcp_observed or "dhcp" in source_text
    has_mdns = mdns_observed or "mdns" in source_text or "dns-sd" in source_text
    has_ssdp = ssdp_observed or "ssdp" in source_text or "upnp" in source_text
    has_snmp = "snmp" in source_text
    has_l2 = "lldp" in source_text or "cdp" in source_text
    has_endpoint = any(token in source_text for token in ("endpoint", "agent inventory"))
    actions: list[dict[str, str]] = []

    def add(priority: str, action: str, reason: str) -> None:
        actions.append({"priority": priority, "action": action, "reason": reason})

    if not has_dhcp:
        dhcp_state = str(device.get("dhcp_capture_status") or "").upper()
        dhcp_attempted = bool(device.get("dhcp_investigation_attempted"))
        if dhcp_state in {"UNAVAILABLE", "ERROR", "STOPPED", "NO_INTERFACE", "FAILED", "DEGRADED"}:
            add(
                "LOW",
                "DHCP collection is unavailable; wait for a supported capture interface or use another evidence source.",
                f"DHCP collector state is {dhcp_state}. Repeating the same DHCP recommendation is unlikely to add evidence.",
            )
        elif dhcp_attempted:
            add(
                "LOW",
                "Wait for naturally occurring DHCP lease or renewal traffic; do not force a renewal.",
                "A DHCP collection attempt has already been made without an observation. Retry only after the capture path or network conditions change.",
            )
        else:
            add(
                "HIGH",
                "Observe DHCP identity evidence during normal lease acquisition or renewal.",
                "No DHCP client fingerprint is currently associated with this device. Passive capture may miss leases on switched or isolated Wi-Fi networks; do not force a lease renewal.",
            )
    if authorised and not has_mdns:
        add(
            "MEDIUM",
            "Run the bounded, authorised mDNS/DNS-SD browse and correlate advertisements by source IP.",
            "No mDNS/DNS-SD evidence is stored for this device. Advertisements are optional and absence does not rule out a device capability.",
        )
    elif not has_mdns:
        add(
            "MEDIUM",
            "Retain passive mDNS observations; only run active DNS-SD browsing after this network is authorised.",
            "Active discovery is not recommended until the current network has explicit approval.",
        )
    if authorised and not has_ssdp:
        add(
            "MEDIUM",
            "Run the existing rate-limited SSDP discovery and retain device-reported fields as unverified claims.",
            "No SSDP/UPnP identity evidence is associated with this device.",
        )
    elif not has_ssdp:
        add(
            "LOW",
            "Use passive SSDP observations until active discovery is authorised.",
            "No SSDP/UPnP evidence is currently available.",
        )
    if authorised and not has_nmap:
        add(
            "HIGH",
            "Run a bounded authorised TCP service and OS fingerprint pass for this host.",
            "No Nmap/service fingerprint evidence is associated with this device.",
        )
    if not has_snmp:
        add(
            "LOW",
            "If this is managed infrastructure and read-only SNMPv3 credentials are configured, collect sysDescr, sysObjectID and sysName.",
            "SNMP can provide strong device-reported identity, but NetworkRadar must not guess, brute-force or try default credentials.",
        )
    if not has_l2:
        add(
            "LOW",
            "If the device is on a managed switch, correlate authorised LLDP/CDP observations from the switch or local segment.",
            "Layer-2 neighbour information may reveal a system name, port or device description; it may not be visible from a Wi-Fi client.",
        )
    if not has_endpoint:
        add(
            "HIGH" if not _present(device.get("model")) else "LOW",
            "For an exact hardware model, enrol the NetworkRadar endpoint agent only on a device you administer.",
            "Network fingerprints cannot reliably establish exact hardware model, serial number, CPU or RAM. Authenticated endpoint inventory is required for those fields.",
        )

    profile = device.get("recognition") or device.get("identity_profile") or {}
    if not isinstance(profile, Mapping):
        profile = {}
    category = str(
        profile.get("selected_category")
        or device.get("device_type")
        or "Unclassified network device"
    )
    confidence = device.get("identification_confidence", profile.get("confidence", 0))
    try:
        confidence = max(0, min(100, int(confidence or 0)))
    except (TypeError, ValueError):
        confidence = 0
    model = str(device.get("model") or profile.get("model") or "").strip()
    manufacturer = str(
        device.get("reported_manufacturer") or profile.get("manufacturer") or ""
    ).strip()

    return {
        "ip": str(device.get("ip") or ""),
        "category": category,
        "confidence": confidence,
        "identity_status": (
            "HIGH_CONFIDENCE" if confidence >= 80 else
            "PROBABLE" if confidence >= 58 else
            "LOW_EVIDENCE" if confidence > 0 else "UNKNOWN"
        ),
        "manufacturer": manufacturer or "Not established",
        "model": model or "Not established",
        "model_status": "DEVICE_REPORTED" if model else "NOT_ESTABLISHED",
        "evidence_sources": sources,
        "evidence_source_count": len(sources),
        "authorised_active_discovery": bool(authorised),
        "next_actions": actions[:8],
        "investigation_plan": plan_investigation_methods(
            device, sources,
            device.get("investigation_attempts") if isinstance(device.get("investigation_attempts"), Mapping) else {},
            authorised=authorised,
        ),
        "limitations": [
            "Recommendations are guidance only; this function does not send network traffic.",
            "A MAC address-block registrant is not necessarily the physical device manufacturer.",
            "Exact hardware model and serial number require authenticated endpoint or explicit device-reported evidence.",
            "A missing protocol observation is not proof that the device does not support that protocol.",
        ],
    }
