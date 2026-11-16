"""Evidence-centric device profiling for NetworkRadar.

The profiler distinguishes:
- physical-device identity (manufacturer/model reported by an endpoint),
- device family / role,
- operating-system family,
- network-interface allocation (IEEE OUI),
- observed services and capabilities.

It uses independent evidence families, caps repeated signals from one family,
retains competing hypotheses, and never treats a randomized MAC or OUI as a
device-model identifier. Confidence values are heuristic evidence scores, not
statistical probabilities.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Mapping


_PLACEHOLDERS = {"", "-", "unknown", "unavailable", "none", "n/a",
                 "not observed", "not yet fingerprinted", "unclassified",
                 "unclassified network device"}

# Family reliabilities are conservative starting weights. Multiple fields
# from one family are collapsed to the strongest contribution.
_FAMILY_RELIABILITY = {
    "network_role": 1.00,
    "endpoint_agent": 0.98,
    "snmp": 0.93,
    "upnp": 0.91,
    "nmap_script": 0.88,
    "nmap_os": 0.86,
    "nmap_service": 0.79,
    "service_probe": 0.76,
    "mdns": 0.72,
    "dhcp": 0.82,
    "lldp": 0.76,
    "reported_name": 0.56,
    "reverse_dns": 0.42,
    "tcpip": 0.30,
    "port": 0.16,
    "oui": 0.0,
}

# Each rule is a family -> (pattern, strength, explanation) mapping.
# NIC OUI is intentionally absent from every device-family rule.
_RULES = {
    "Android mobile device": {
        "reported_name": (r"\b(android|samsung galaxy|galaxy [a-z0-9]+|pixel [0-9a-z]+|oneplus|redmi|xiaomi|oppo|vivo|realme|huawei (?:p|mate|nova)|honor)\b", 0.76, "Mobile-device name token"),
        "dhcp": (r"\bandroid[-_ ]dhcp\b|\bandroid mobile client\b", 0.96, "Android DHCP vendor-class fingerprint"),
        "nmap_os": (r"\bandroid\b", 0.86, "Nmap OS fingerprint reports Android"),
        "snmp": (r"\bandroid\b", 0.72, "SNMP system description reports Android"),
        "upnp": (r"\bandroid\b", 0.65, "UPnP device-reported Android platform"),
        "endpoint_agent": (r"\b(android|pixel|samsung galaxy|oneplus|xiaomi|redmi|oppo|vivo)\b", 0.98, "Authenticated endpoint inventory identifies mobile platform"),
    },
    "Apple mobile device": {
        "reported_name": (r"\b(iphone|ipad|ipod|ios device)\b", 0.78, "Apple mobile-device name"),
        "nmap_os": (r"\b(ios|iphone os|ipad os)\b", 0.88, "Nmap OS fingerprint reports iOS"),
        "upnp": (r"\b(iphone|ipad|ios)\b", 0.62, "UPnP device-reported Apple mobile platform"),
        "mdns": (r"_apple-mobdev2\._tcp|_companion-link\._tcp", 0.62, "Apple mobile ecosystem service"),
    },
    "Apple computer": {
        "reported_name": (r"\b(macbook|imac|mac mini|mac studio|mac pro|macos|mac os|darwin)\b", 0.78, "Apple computer name/platform"),
        "nmap_os": (r"\b(mac os|macos|darwin)\b", 0.86, "Nmap OS fingerprint reports macOS"),
        "mdns": (r"_device-info\._tcp.*mac|model=mac", 0.55, "Apple device information service"),
        "endpoint_agent": (r"\b(macos|macbook|imac|mac mini|darwin)\b", 0.96, "Authenticated endpoint inventory reports Apple platform"),
    },
    "Windows computer": {
        "reported_name": (r"\b(windows|win10|win11|thinkpad|elitebook|latitude|optiplex|probook|surface pro|surface laptop)\b", 0.70, "Windows/computer name token"),
        "nmap_os": (r"\b(windows|microsoft)\b", 0.91, "Nmap OS fingerprint reports Windows"),
        "nmap_script": (r"\bwindows (?:10|11|server)|microsoft windows|smb-os-discovery", 0.86, "SMB/Nmap host script reports Windows"),
        "snmp": (r"\b(windows|microsoft)\b", 0.75, "SNMP system description reports Windows"),
        "dhcp": (r"\bmsft\s*\d", 0.72, "Microsoft DHCP vendor-class identifier"),
        "endpoint_agent": (r"\b(windows|thinkpad|elitebook|latitude|optiplex|probook|surface)\b", 0.98, "Authenticated endpoint OS/hardware inventory"),
    },
    "Linux / Unix computer": {
        "reported_name": (r"\b(ubuntu|debian|fedora|arch linux|freebsd|openbsd|linux workstation)\b", 0.66, "Linux/Unix name token"),
        "nmap_os": (r"\b(linux|freebsd|openbsd|netbsd|unix)\b", 0.87, "Nmap OS fingerprint reports Unix-like OS"),
        "nmap_script": (r"\b(linux|ubuntu|debian|freebsd|openbsd)\b", 0.76, "Nmap service/host script reports Unix-like OS"),
        "snmp": (r"\b(linux|freebsd|openbsd|unix)\b", 0.76, "SNMP system description reports Unix-like OS"),
        "dhcp": (r"\b(dhcpcd|busybox|udhcp)\b", 0.52, "DHCP client implementation is Unix-like; device role remains unknown"),
        "endpoint_agent": (r"\b(linux|ubuntu|debian|fedora|freebsd|openbsd|unix)\b", 0.96, "Authenticated endpoint inventory reports Unix-like OS"),
    },
    "Printer": {
        "reported_name": (r"\b(printer|laserjet|deskjet|officejet|epson|brother|canon|xerox|ricoh|kyocera)\b", 0.72, "Printer model/name token"),
        "upnp": (r"\b(printer|print server|laserjet|deskjet|officejet|epson|brother|canon)\b", 0.84, "UPnP device description identifies printer"),
        "mdns": (r"_ipp\._tcp|_ipps\._tcp|_printer\._tcp|_pdl-datastream\._tcp", 0.84, "DNS-SD printing service"),
        "nmap_service": (r"\b(ipp|printer|jetdirect|pdl-datastream)\b", 0.78, "Nmap identifies a printing service"),
        "nmap_script": (r"\b(printer|laserjet|deskjet|epson|canon|brother)\b", 0.80, "Nmap printer discovery script"),
        "snmp": (r"\b(printer|laserjet|deskjet|epson|canon|brother)\b", 0.84, "SNMP system description identifies printer"),
    },
    "IP camera / surveillance": {
        "reported_name": (r"\b(ip.?cam|camera|cctv|hikvision|dahua|axis camera|nvr camera)\b", 0.70, "Camera name/vendor token"),
        "upnp": (r"\b(onvif|ip.?camera|network camera|surveillance camera|hikvision|dahua)\b", 0.87, "UPnP device description identifies camera"),
        "mdns": (r"_onvif\._tcp|_rtsp\._tcp", 0.80, "Camera/ONVIF DNS-SD service"),
        "nmap_service": (r"\b(rtsp|onvif)\b", 0.76, "Nmap identifies RTSP/ONVIF service"),
        "nmap_script": (r"\b(onvif|network camera|hikvision|dahua)\b", 0.82, "Nmap discovery script identifies camera"),
        "snmp": (r"\b(camera|hikvision|dahua|axis)\b", 0.80, "SNMP description identifies camera platform"),
    },
    "Smart TV / media streamer": {
        "reported_name": (r"\b(chromecast|google tv|fire tv|roku|smart.?tv|webos|tizen|bravia|appletv|apple tv)\b", 0.70, "Media-device name token"),
        "upnp": (r"\b(mediarenderer|smart.?tv|chromecast|roku|fire.?tv|bravia|webos|tizen|dlna)\b", 0.84, "UPnP media-renderer/device description"),
        "mdns": (r"_mediaremotetv\._tcp", 0.78, "Apple TV media-remote DNS-SD service"),
        "nmap_service": (r"\b(dial|plex|dlna|upnp)\b", 0.66, "Nmap identifies a media service"),
    },
    "Media receiver / streamer": {
        "mdns": (r"_googlecast\._tcp|_airplay\._tcp|_raop\._tcp|_mediaremotetv\._tcp|_spotify-connect\._tcp", 0.94, "Media receiver/streaming service; physical form factor not established"),
        "upnp": (r"\b(google cast|chromecast|media renderer|dlna renderer)\b", 0.78, "UPnP media receiver description"),
    },
    "Smart speaker / audio": {
        "reported_name": (r"\b(sonos|homepod|echo dot|echo show|smart speaker|bose speaker)\b", 0.72, "Audio-device name token"),
        "upnp": (r"\b(sonos|homepod|smart speaker|audio renderer)\b", 0.84, "UPnP audio-device description"),
        "mdns": (r"_sonos\._tcp", 0.78, "Sonos audio-device DNS-SD service"),
    },
    "Gaming console": {
        "reported_name": (r"\b(xbox|playstation|ps[345]|nintendo switch)\b", 0.78, "Gaming platform name"),
        "upnp": (r"\b(xbox|playstation|nintendo)\b", 0.82, "UPnP gaming-platform description"),
        "nmap_service": (r"\b(xbox|playstation|nintendo)\b", 0.70, "Nmap service banner identifies gaming platform"),
    },
    "NAS / network storage": {
        "reported_name": (r"\b(synology|diskstation|qnap|truenas|freenas|asustor|terramaster|nas[0-9-])\b", 0.74, "NAS platform name"),
        "upnp": (r"\b(synology|diskstation|qnap|truenas|freenas|asustor|nas)\b", 0.84, "UPnP description identifies storage platform"),
        "nmap_service": (r"\b(smb|afp|nfs|iscsi)\b", 0.45, "File/storage services observed"),
        "nmap_script": (r"\b(synology|qnap|truenas|freenas|diskstation)\b", 0.84, "Nmap script identifies NAS platform"),
        "snmp": (r"\b(synology|qnap|truenas|freenas|nas)\b", 0.80, "SNMP description identifies NAS platform"),
    },
    "Router / firewall": {
        "network_role": (r".*", 1.0, "Default gateway role observed"),
        "reported_name": (r"\b(router|gateway|firewall|mikrotik|routeros|openwrt|opnsense|pfsense|fortigate|sonicwall)\b", 0.70, "Network-appliance name token"),
        "upnp": (r"\b(internet gateway device|igd|router|firewall|mikrotik|openwrt|routeros)\b", 0.86, "UPnP router/device description"),
        "nmap_service": (r"\b(dns|dhcp|ssh|https|snmp)\b", 0.25, "Network-management services observed"),
        "snmp": (r"\b(router|firewall|mikrotik|routeros|openwrt|opnsense|pfsense|fortigate|sonicwall)\b", 0.88, "SNMP description identifies network appliance"),
    },
    "Wireless access point": {
        "reported_name": (r"\b(access.?point|wireless controller|unifi ap|ruckus|aruba|omada ap)\b", 0.74, "Wireless infrastructure name"),
        "upnp": (r"\b(access.?point|wireless controller|unifi ap|ruckus|aruba|omada)\b", 0.86, "UPnP description identifies access point"),
        "snmp": (r"\b(access.?point|wireless controller|ruckus|aruba|unifi)\b", 0.88, "SNMP description identifies wireless infrastructure"),
        "lldp": (r"\b(access.?point|wireless controller|unifi|ruckus|aruba)\b", 0.72, "LLDP/CDP system description identifies access point"),
    },
    "VoIP phone / telephony": {
        "reported_name": (r"\b(yealink|polycom|grandstream|voip|sip phone)\b", 0.72, "VoIP endpoint name"),
        "upnp": (r"\b(yealink|polycom|grandstream|voip phone)\b", 0.82, "UPnP description identifies telephony endpoint"),
        "mdns": (r"_sip\._tcp|_sips\._tcp", 0.65, "SIP DNS-SD service"),
        "nmap_service": (r"\b(sip|rtp|h323)\b", 0.60, "Nmap identifies telephony service"),
    },
    "Smart-home / IoT": {
        "reported_name": (r"\b(tasmota|shelly|tuya|zigbee|zwave|thermostat|smart plug|home assistant)\b", 0.66, "Smart-home product/name token"),
        "upnp": (r"\b(tasmota|shelly|tuya|home assistant|smart plug|thermostat)\b", 0.82, "UPnP smart-home description"),
        "mdns": (r"_hap\._tcp|_matter\._tcp|_home-assistant\._tcp|_ewelink\._tcp", 0.78, "Smart-home DNS-SD service"),
        "nmap_service": (r"\b(mqtt|coap|matter)\b", 0.62, "Nmap identifies IoT protocol"),
    },
    "Server / infrastructure host": {
        "reported_name": (r"\b(server|domain controller|hypervisor|proxmox|esxi|vmware)\b", 0.62, "Server/infrastructure name"),
        "nmap_os": (r"\b(server|windows server|linux)\b", 0.48, "Nmap OS/server signature"),
        "nmap_script": (r"\b(domain|forest|server|active directory)\b", 0.70, "Nmap host script reports server role"),
        "snmp": (r"\b(server|domain controller|hypervisor)\b", 0.68, "SNMP system description reports server role"),
    },
    "UPS / power equipment": {
        "reported_name": (r"\b(ups|apc smart|eaton power|powerware)\b", 0.72, "Power equipment name"),
        "snmp": (r"\b(apc|eaton|powerware|ups)\b", 0.86, "SNMP system description identifies power equipment"),
    },
    "Access control / intercom": {
        "reported_name": (r"\b(doorbell|intercom|access control|badge reader|biometric)\b", 0.68, "Access-control name token"),
        "upnp": (r"\b(doorbell|intercom|access control|badge reader)\b", 0.80, "UPnP access-control description"),
        "nmap_service": (r"\b(doorbell|intercom|access control)\b", 0.65, "Service banner identifies access control"),
    },
    "Smart appliance": {
        "reported_name": (r"\b(refrigerator|washing machine|dishwasher|air.?condition|smart appliance|oven)\b", 0.66, "Appliance name token"),
        "upnp": (r"\b(refrigerator|washing machine|dishwasher|air.?condition|smart appliance)\b", 0.80, "UPnP appliance description"),
    },
}


def _text(value: Any, limit: int = 500) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _present(value: Any) -> bool:
    return _text(value, 500).casefold() not in _PLACEHOLDERS


def _add(facts: list[dict], family: str, value: Any, source: str,
         reliability: float | None = None, evidence_class: str = "OBSERVED") -> None:
    value = _text(value)
    if not _present(value):
        return
    rel = _FAMILY_RELIABILITY.get(family, 0.5) if reliability is None else reliability
    facts.append({
        "family": family, "value": value, "source": source,
        "reliability": max(0.0, min(1.0, float(rel))),
        "evidence_class": evidence_class,
    })


def _extract_script_values(scripts: Any) -> list[tuple[str, str]]:
    output = []
    for item in list(scripts or [])[:64]:
        if not isinstance(item, Mapping):
            continue
        script_id = _text(item.get("id") or item.get("script_id"), 80)
        raw = _text(item.get("output") or item.get("text"), 4000)
        if script_id or raw:
            output.append((script_id, raw))
        data = item.get("data") or item.get("elements") or {}
        if isinstance(data, Mapping):
            for key, value in list(data.items())[:32]:
                if isinstance(value, (str, int, float)):
                    output.append((script_id or "Nmap script", f"{key}: {_text(value, 300)}"))
    return output


def _service_names(device: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for row in device.get("nmap_service_intel", []) or []:
        if isinstance(row, Mapping):
            name = _text(row.get("name"), 80).casefold()
            if name:
                names.add(name)
    for value in device.get("services_found", []) or []:
        text = _text(value, 240).casefold()
        match = re.match(r"^\s*\d+/(?:tcp/|udp/)?([a-z0-9_.+-]+)", text)
        if match:
            names.add(match.group(1))
    for row in device.get("service_intel", []) or []:
        if isinstance(row, Mapping):
            for key in ("service", "name", "server", "banner"):
                value = _text(row.get(key), 180).casefold()
                if value:
                    names.add(value)
    return names


def _build_facts(device: Mapping[str, Any]) -> list[dict]:
    facts: list[dict] = []
    if device.get("_is_gateway"):
        _add(facts, "network_role", "default gateway", "Default-route interface", 1.0)

    # User/client-supplied names are useful clues but are not treated as unique IDs.
    for key, label in (("hostname", "DHCP/reverse-resolved hostname"),
                       ("friendly_name", "Device-advertised friendly name")):
        value = device.get(key)
        if key == "hostname" and _text(value).casefold() == _text(device.get("ip")).casefold():
            continue
        _add(facts, "reported_name", value, label, 0.60 if key == "friendly_name" else 0.52,
             "DEVICE_REPORTED")

    if device.get("reported_manufacturer"):
        _add(facts, "upnp", device["reported_manufacturer"], "UPnP-reported manufacturer", 0.91, "DEVICE_REPORTED")
    if device.get("model"):
        _add(facts, "upnp", device["model"], "UPnP-reported model/model number", 0.91, "DEVICE_REPORTED")

    ssdp = device.get("ssdp_intel") or {}
    if isinstance(ssdp, Mapping):
        for key, label in (("friendlyname", "UPnP friendly name"),
                           ("manufacturer", "UPnP manufacturer"),
                           ("modelname", "UPnP model name"),
                           ("modelnumber", "UPnP model number"),
                           ("devicetype", "UPnP device type"),
                           ("ssdp_server", "SSDP server banner")):
            _add(facts, "upnp", ssdp.get(key), label, 0.91, "DEVICE_REPORTED")

    oui = device.get("oui_assignment") or {}
    nic = (oui.get("organization") if isinstance(oui, Mapping) else "") or device.get("vendor", "")
    _add(facts, "oui", nic, "IEEE NIC address-block registrant", 0.15, "OBSERVED")

    os_value = device.get("os_guess", "")
    os_match = device.get("nmap_os_fingerprint") or {}
    if isinstance(os_match, Mapping):
        os_value = os_match.get("name") or os_value
    _add(facts, "nmap_os", os_value, "Nmap TCP/IP OS fingerprint", 0.86, "INFERRED")

    passive = device.get("passive_tcp") or {}
    if isinstance(passive, Mapping):
        _add(facts, "tcpip", passive.get("signature"), "Passive TCP SYN signature", 0.30)
        _add(facts, "tcpip", passive.get("os_family_hint"), "Passive TCP OS-family heuristic", 0.25, "INFERRED")

    for row in device.get("nmap_service_intel", []) or []:
        if not isinstance(row, Mapping):
            continue
        desc = " ".join(_text(row.get(key), 180) for key in ("name", "product", "version", "extrainfo"))
        _add(facts, "nmap_service", desc, f"Nmap service on {row.get('port', '?')}", 0.79, "OBSERVED")

    for row in device.get("service_intel", []) or []:
        if not isinstance(row, Mapping):
            continue
        desc = " ".join(_text(row.get(key), 180) for key in ("banner", "server", "http_title", "api_identity"))
        _add(facts, "service_probe", desc, f"Active service probe on {row.get('port', '?')}", 0.76, "OBSERVED")
        api_key = _text(row.get("api_identity_key"), 40).casefold()
        api_value = row.get("api_identity")
        if api_key == "model":
            _add(facts, "upnp", api_value, "HTTP device API model field", 0.78, "DEVICE_REPORTED")
        elif api_key == "manufacturer":
            _add(facts, "upnp", api_value, "HTTP device API manufacturer field", 0.78, "DEVICE_REPORTED")

    for row in device.get("dhcp_identity", []) or []:
        if isinstance(row, Mapping):
            _add(facts, "dhcp", row.get("vendor_class"), "DHCP option 60 vendor class", 0.86, "DEVICE_REPORTED")
            _add(facts, "dhcp", row.get("hostname"), "DHCP option 12 hostname", 0.55, "DEVICE_REPORTED")
            _add(facts, "dhcp", row.get("user_class"), "DHCP option 77 user class", 0.62, "DEVICE_REPORTED")
            _add(facts, "dhcp", row.get("client_fqdn"), "DHCP option 81 client FQDN", 0.62, "DEVICE_REPORTED")
    for item in device.get("dhcp_intelligence", []) or []:
        if isinstance(item, Mapping):
            _add(facts, "dhcp", item.get("category") + " " + item.get("reason", "")
                 if item.get("category") else item.get("reason"),
                 "Interpreted DHCP client fingerprint", 0.82, "INFERRED")

    mdns = device.get("mdns_records", "")
    if isinstance(mdns, (list, tuple)):
        mdns = " | ".join(_text(x, 250) for x in mdns)
    _add(facts, "mdns", mdns, "mDNS/DNS-SD service observations", 0.72, "DEVICE_REPORTED")

    snmp = device.get("snmp_intel") or {}
    if isinstance(snmp, Mapping):
        for key in ("sysDescr", "sysObjectID", "sysName"):
            _add(facts, "snmp", snmp.get(key), f"SNMPv3 {key}", 0.93, "DEVICE_REPORTED")

    l2 = device.get("lldp_cdp") or {}
    if isinstance(l2, Mapping):
        _add(facts, "lldp", l2.get("name"), "LLDP/CDP system name", 0.76, "DEVICE_REPORTED")
        _add(facts, "lldp", l2.get("description"), "LLDP/CDP system description", 0.76, "DEVICE_REPORTED")

    for script_id, output in _extract_script_values(device.get("nmap_script_intel")):
        _add(facts, "nmap_script", script_id + " " + output,
             f"Nmap safe script: {script_id}", 0.88, "DEVICE_REPORTED")

    endpoint = device.get("endpoint_inventory") or device.get("agent_inventory") or {}
    if isinstance(endpoint, Mapping):
        for key in ("manufacturer", "model", "system_manufacturer", "system_model",
                    "product_name", "os_name", "os_version", "computer_name"):
            _add(facts, "endpoint_agent", endpoint.get(key), f"Enrolled endpoint inventory: {key}",
                 0.98, "DEVICE_REPORTED")
        _add(facts, "endpoint_agent", endpoint.get("system_family"),
             "Enrolled endpoint inventory: system family", 0.98, "DEVICE_REPORTED")
        os_data = endpoint.get("operating_system") or {}
        if isinstance(os_data, Mapping):
            _add(facts, "endpoint_agent", " ".join(
                _text(os_data.get(key), 120) for key in ("caption", "name", "version")
            ), "Enrolled endpoint inventory: operating system", 0.99, "DEVICE_REPORTED")

    return facts


def _score_categories(facts: list[dict], device: Mapping[str, Any]) -> tuple[list, list, list]:
    contributions: dict[str, dict[str, tuple[float, dict]]] = defaultdict(dict)
    matches = []
    for category, family_rules in _RULES.items():
        for family, (pattern, strength, reason) in family_rules.items():
            for fact in facts:
                if fact["family"] != family:
                    continue
                if not re.search(pattern, fact["value"], re.I):
                    continue
                score = strength * fact["reliability"]
                old = contributions[category].get(family)
                if old is None or score > old[0]:
                    contributions[category][family] = (score, fact)
                    matches.append({
                        "category": category, "source_family": family,
                        "source": fact["source"], "matched": reason,
                        "weight": round(score, 3), "value": fact["value"][:180],
                    })

    # Service names are normalised before combinations are evaluated. This
    # fixes the old exact-set comparison against strings such as "80/http".
    service_names = _service_names(device)
    ports = {int(x) for x in device.get("port_numbers", []) if str(x).isdigit()}
    combos = [
        ({"ipp", "http"}, "Printer", 0.84, "IPP + HTTP service combination"),
        ({"rtsp", "http"}, "IP camera / surveillance", 0.68, "RTSP + HTTP service combination"),
        ({"smb", "http"}, "NAS / network storage", 0.52, "SMB + HTTP; storage role remains tentative"),
        ({"ssh", "http"}, "Linux / Unix computer", 0.42, "SSH + HTTP; Unix role remains tentative"),
    ]
    for required, category, strength, reason in combos:
        if required.issubset(service_names):
            family = "nmap_service"
            score = strength * _FAMILY_RELIABILITY[family]
            old = contributions[category].get(family)
            if old is None or score > old[0]:
                contributions[category][family] = (score, {
                    "family": family, "source": "Nmap service combination",
                    "value": reason, "reliability": _FAMILY_RELIABILITY[family],
                })
                matches.append({"category": category, "source_family": family,
                                "source": "Nmap service combination",
                                "matched": reason, "weight": round(score, 3),
                                "value": reason})

    # Ports are context only: they never independently establish a device type.
    port_clues = []
    for required, label in (({631, 9100}, "Printer services"),
                            ({554, 80}, "RTSP/HTTP services"),
                            ({445, 5000}, "SMB/web services"),
                            ({5060, 5061}, "SIP services")):
        if required.issubset(ports):
            port_clues.append(label)

    ranked = []
    for category, family_values in contributions.items():
        vals = sorted((entry[0] for entry in family_values.values()), reverse=True)
        remaining = 1.0
        for index, value in enumerate(vals):
            scale = 0.90 if index == 0 else 0.72
            remaining *= 1.0 - min(0.95, value * scale)
        score = int(round((1.0 - remaining) * 100))
        ranked.append({
            "category": category, "confidence": min(96, score),
            "source_families": sorted(family_values),
            "evidence": [entry[1] for entry in family_values.values()],
        })
    ranked.sort(key=lambda row: (row["confidence"], row["category"]), reverse=True)
    return ranked, port_clues, matches


def _extract_reported_model(device: Mapping[str, Any]) -> str:
    endpoint = device.get("endpoint_inventory") or {}
    if isinstance(endpoint, Mapping) and _present(endpoint.get("model")):
        return _text(endpoint.get("model"), 160)
    ssdp = device.get("ssdp_intel") or {}
    if isinstance(ssdp, Mapping):
        model = _text(ssdp.get("modelname"), 120)
        number = _text(ssdp.get("modelnumber"), 80)
        if _present(model):
            return " ".join(x for x in (model, number if _present(number) else "") if x)
    if _present(device.get("model")):
        return _text(device.get("model"), 160)
    for row in device.get("service_intel", []) or []:
        if isinstance(row, Mapping) and _text(row.get("api_identity_key")).casefold() == "model":
            if _present(row.get("api_identity")):
                return _text(row.get("api_identity"), 160)
    for script_id, output in _extract_script_values(device.get("nmap_script_intel")):
        if script_id == "upnp-info":
            match = re.search(r"^\s*Model(?: Name)?:\s*(.+)$", output, re.I | re.M)
            if match:
                return _text(match.group(1), 160)
    return ""


def _extract_reported_manufacturer(device: Mapping[str, Any]) -> str:
    endpoint = device.get("endpoint_inventory") or {}
    if isinstance(endpoint, Mapping) and _present(endpoint.get("manufacturer")):
        return _text(endpoint.get("manufacturer"), 160)
    ssdp = device.get("ssdp_intel") or {}
    if isinstance(ssdp, Mapping) and _present(ssdp.get("manufacturer")):
        return _text(ssdp.get("manufacturer"), 160)
    if _present(device.get("reported_manufacturer")):
        return _text(device.get("reported_manufacturer"), 160)
    for row in device.get("service_intel", []) or []:
        if isinstance(row, Mapping) and _text(row.get("api_identity_key")).casefold() == "manufacturer":
            if _present(row.get("api_identity")):
                return _text(row.get("api_identity"), 160)
    for script_id, output in _extract_script_values(device.get("nmap_script_intel")):
        if script_id == "upnp-info":
            match = re.search(r"^\s*Manufacturer:\s*(.+)$", output, re.I | re.M)
            if match:
                return _text(match.group(1), 160)
    return ""


def _os_assessment(device: Mapping[str, Any], facts: list[dict]) -> dict:
    candidates = []
    nmap = _text(device.get("os_guess"), 200)
    if _present(nmap) and nmap != "Not yet fingerprinted":
        candidates.append(("Nmap", nmap, 0.86))
    snmp = device.get("snmp_intel") or {}
    if isinstance(snmp, Mapping) and _present(snmp.get("sysDescr")):
        candidates.append(("SNMPv3 sysDescr", _text(snmp["sysDescr"], 200), 0.90))
    for script_id, output in _extract_script_values(device.get("nmap_script_intel")):
        if script_id == "smb-os-discovery":
            match = re.search(r"^\s*OS:\s*(.+)$", output, re.I | re.M)
            if match:
                candidates.append(("Nmap SMB OS discovery", _text(match.group(1), 200), 0.90))
    for dhcp_row in device.get("dhcp_identity", []) or []:
        if not isinstance(dhcp_row, Mapping):
            continue
        vendor_class = _text(dhcp_row.get("vendor_class"), 180)
        if re.search(r"\bandroid[-_ ]dhcp\b", vendor_class, re.I):
            candidates.append(("DHCP client fingerprint (inferred)", "Android client stack (vendor class)", 0.72))
        elif re.search(r"\bmsft\s*\d", vendor_class, re.I):
            candidates.append(("DHCP client fingerprint (inferred)", "Microsoft Windows client stack (vendor class)", 0.64))
    endpoint = device.get("endpoint_inventory") or {}
    if isinstance(endpoint, Mapping):
        os_data = endpoint.get("operating_system") or {}
        if isinstance(os_data, Mapping):
            endpoint_os = " ".join(_text(os_data.get(key), 120)
                                   for key in ("caption", "name", "version", "build"))
            if _present(endpoint_os):
                candidates.append(("Authenticated endpoint inventory", endpoint_os, 0.99))
        elif _present(os_data):
            candidates.append(("Authenticated endpoint inventory", _text(os_data, 200), 0.99))
    family = ""
    text = " ".join(value.lower() for _, value, _ in candidates)
    if re.search(r"\bandroid\b", text):
        family = "Android"
    elif re.search(r"\b(ios|iphone os)\b", text):
        family = "iOS"
    elif re.search(r"\bwindows\b", text):
        family = "Windows"
    elif re.search(r"\b(mac os|macos|darwin)\b", text):
        family = "macOS"
    elif re.search(r"\b(linux|ubuntu|debian|fedora|freebsd|openbsd)\b", text):
        family = "Linux / Unix"
    elif re.search(r"\b(embedded|busybox|udhcp)\b", text):
        family = "Embedded / appliance OS"
    if not candidates:
        return {"family": "", "candidates": [], "status": "NOT_OBSERVED"}
    return {
        "family": family, "candidates": [
            {"source": source, "value": value, "reliability": reliability}
            for source, value, reliability in candidates
        ],
        "status": "OBSERVED" if family else "UNRESOLVED",
        "note": "OS-family assessment; it is not a device model or exact OS build.",
    }


def analyse_device_profile(device: Mapping[str, Any] | None) -> dict:
    """Build an explainable, conservative device identity profile."""
    device = device or {}
    facts = _build_facts(device)
    ranked, port_clues, match_records = _score_categories(facts, device)
    best = ranked[0] if ranked else {"category": "Unclassified network device",
                                     "confidence": 0, "source_families": [], "evidence": []}
    runner = ranked[1] if len(ranked) > 1 else None
    conflict = bool(runner and runner["confidence"] >= 45
                    and best["confidence"] - runner["confidence"] < 12)
    if conflict:
        category = f"Ambiguous: {best['category']} / {runner['category']}"
        confidence = max(20, best["confidence"] - 15)
        selected = "Unclassified network device"
    else:
        category = best["category"]
        confidence = best["confidence"]
        selected = category if confidence >= 58 else "Unclassified network device"

    if device.get("_is_gateway"):
        category = selected = "Router / firewall"
        confidence = 98
        conflict = False

    model = _extract_reported_model(device)
    manufacturer = _extract_reported_manufacturer(device)
    oui = device.get("oui_assignment") or {}
    nic_manufacturer = (
        _text(oui.get("organization"), 160) if isinstance(oui, Mapping)
        else _text(device.get("vendor"), 160)
    ) or _text(device.get("vendor"), 160)
    os_profile = _os_assessment(device, facts)

    evidence_families = sorted({fact["family"] for fact in facts})
    status = ("HIGH" if confidence >= 80 else "PROBABLE" if confidence >= 58
              else "LOW" if confidence else "UNKNOWN")
    alternatives = [
        {"category": row["category"], "confidence": row["confidence"],
         "source_families": row["source_families"]}
        for row in ranked[1:5]
    ]
    return {
        "category": category,
        "selected_category": selected,
        "confidence": confidence,
        "status": status,
        "model": model,
        "manufacturer": manufacturer,
        "nic_manufacturer": nic_manufacturer,
        "nic_address_block_registrant": dict(oui) if isinstance(oui, Mapping) else {},
        "operating_system": os_profile,
        "passive_tcp_os_hint": (device.get("passive_tcp") or {}).get("os_family_hint", ""),
        "evidence": facts,
        "matches": match_records[:128],
        "ranked_categories": [
            {"category": row["category"], "confidence": row["confidence"],
             "source_families": row["source_families"]}
            for row in ranked[:8]
        ],
        "alternatives": alternatives,
        "conflicting_classifications": conflict,
        "source_families": evidence_families,
        "evidence_count": len(facts),
        "collection_notes": [_text(x, 240) for x in device.get("collection_notes", []) if _present(x)],
        "tcp_ports": sorted({int(x) for x in device.get("port_numbers", []) if str(x).isdigit()}),
        "udp_ports": sorted({int(x) for x in device.get("udp_port_numbers", []) if str(x).isdigit()}),
        "nmap_scripts": sorted({item[0] for item in _extract_script_values(device.get("nmap_script_intel")) if item[0]}),
        "port_clues": port_clues,
        "limitations": [
            "Confidence is an explainable heuristic evidence score, not a probability.",
            "A locally administered MAC is not a stable hardware identifier.",
            "An IEEE OUI identifies a NIC address-block registrant, not necessarily the device maker.",
            "Exact model and manufacturer are shown only when explicitly reported by the endpoint/service.",
            "mDNS, DHCP, hostnames, banners and UPnP fields can be absent, generic or spoofed.",
        ],
    }
