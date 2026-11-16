"""Evidence coverage metrics for the NetworkRadar device dossier.

Coverage measures how much information has been collected across identity
domains. It is deliberately not a probability or a confidence score.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    text = str(value).strip()
    return text.casefold() not in {"", "-", "unknown", "unavailable", "not observed",
                                   "not reported", "not yet fingerprinted", "none", "n/a"}


def assess_identity_quality(
    device: Mapping[str, Any] | None,
    *,
    facts: Iterable[Mapping[str, Any]] | None = None,
    recognition: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return domain-level evidence coverage without inflating identity certainty."""
    device = device or {}
    recognition = recognition or device.get("recognition") or {}
    facts = list(facts if facts is not None else recognition.get("evidence", []) or [])
    oui = device.get("oui_assignment") or recognition.get("nic_address_block_registrant") or {}
    passive = device.get("passive_tcp") or {}
    ssdp = device.get("ssdp_intel") or {}

    domains = [
        ("hardware", "Hardware", [
            device.get("mac"), device.get("reported_manufacturer"),
            device.get("model"), oui.get("organization") if isinstance(oui, Mapping) else "",
        ]),
        ("operating_system", "Operating system", [
            device.get("os_guess"), passive.get("os_family_hint"),
        ]),
        ("network", "Network identity", [
            device.get("ip"), device.get("mac"), device.get("hostname"),
            device.get("device_name"), device.get("friendly_name"),
            device.get("mdns_records"),
        ]),
        ("services", "Services", [
            device.get("open_ports"), device.get("service_summary"),
            device.get("nmap_service_intel"), device.get("service_intel"),
            device.get("mdns_records") or ssdp.get("devicetype"),
        ]),
        ("classification", "Device classification", [
            recognition.get("category") if recognition.get("category") not in
            {"", "Unclassified network device", "Unknown"} else "",
            recognition.get("matches"),
        ]),
        ("evidence", "Identity evidence", [
            facts, device.get("identity_evidence"),
            device.get("identity_assessments"),
        ]),
    ]
    results = []
    for key, label, signals in domains:
        observed = sum(1 for signal in signals if _present(signal))
        total = len(signals)
        results.append({
            "key": key, "label": label, "observed": observed, "total": total,
            "score": round(observed * 100 / total) if total else 0,
        })

    families = sorted({
        str(item.get("family") or "").strip()
        for item in facts
        if isinstance(item, Mapping) and _present(item.get("family"))
    })
    total_evidence = len(facts)
    coverage = round(sum(item["score"] for item in results) / len(results)) if results else 0
    return {
        "coverage_score": coverage,
        "domains": results,
        "evidence_count": total_evidence,
        "independent_families": len(families),
        "source_families": families,
        "limitations": [
            "Coverage measures collected information, not identity probability.",
            "A MAC address-block registrant is not necessarily the device manufacturer.",
            "Exact model identification requires explicit device- or service-reported model evidence.",
        ],
    }
