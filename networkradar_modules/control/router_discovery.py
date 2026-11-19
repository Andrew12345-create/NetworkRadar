"""Read-only identification of the active LAN gateway/router.

Only probes the explicitly authorised default gateway. No credentials are sent,
no configuration is changed, redirects are refused, and response bodies are
strictly size/time bounded.
"""
from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
import re
import socket
import ssl


_VENDOR_PATTERNS = [
    ("MikroTik", ("mikrotik", "routeros", "routerboard", "webfig")),
    ("ASUS", ("asus router", "asuswrt", "asus.com", "asus wireless router")),
    ("TP-Link", ("tp-link", "tplink", "omada", "archer")),
    ("Ubiquiti", ("ubiquiti", "unifi", "edgeos", "uisp")),
    ("NETGEAR", ("netgear", "nighthawk", "orbi")),
    ("D-Link", ("d-link", "dlink", "mydlink")),
    ("Linksys", ("linksys", "velop")),
    ("Huawei", ("huawei", "huawei home gateway", "huawei echolife")),
    ("ZTE", ("zte", "zxhn", "f680", "f660")),
    ("OpenWrt", ("openwrt", "luci", "lede")),
    ("GL.iNet", ("gl.inet", "glinet", "goodcloud")),
    ("DrayTek", ("draytek", "vigor")),
    ("Zyxel", ("zyxel", "keenetic")),
    ("Cisco", ("cisco", "meraki", "catalyst")),
    ("Tenda", ("tenda",)),
    ("Mercusys", ("mercusys",)),
    ("Cudy", ("cudy",)),
    ("TOTOLINK", ("totolink",)),
    ("Nokia", ("nokia", "g-2425g")),
    ("FiberHome", ("fiberhome", "an5506")),
    ("Mitrastar", ("mitrastar",)),
    ("Sagemcom", ("sagemcom",)),
    ("Technicolor", ("technicolor",)),
    ("Arris", ("arris", "surfboard")),
    ("Motorola", ("motorola", "moto router")),
    ("Huawei", ("huawei",)),
]

_PORTS = (80, 443, 8080, 8443)
_MAX_BODY = 16384
_TIMEOUT = 1.35


def _private_target(host: str, network: str) -> str:
    address = ipaddress.ip_address(str(host).strip())
    scope = ipaddress.ip_network(str(network).strip(), strict=False)
    if address.version != 4 or not address.is_private or address not in scope:
        raise ValueError("Router identification is restricted to the authorised private IPv4 subnet.")
    return str(address)


def _probe_http(host: str, port: int) -> dict:
    secure = port in (443, 8443)
    connection = None
    evidence = []
    body_text = ""
    headers = {}
    cert_subject = ""
    try:
        if secure:
            # This connection is strictly for unauthenticated identity metadata.
            # An untrusted certificate is recorded, never accepted for control.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(host, port, timeout=_TIMEOUT, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=_TIMEOUT)
        connection.request("GET", "/", headers={
            "Host": host, "User-Agent": "NetworkRadar-RouterDiscovery/1.0",
            "Accept": "text/html,application/json;q=0.8,*/*;q=0.2",
            "Connection": "close",
        })
        response = connection.getresponse()
        # Do not follow redirects; the Location header itself may disclose the UI path.
        raw = response.read(_MAX_BODY + 1)
        if len(raw) > _MAX_BODY:
            raw = raw[:_MAX_BODY]
        headers = {str(k).lower(): str(v)[:500] for k, v in response.getheaders()}
        body_text = raw.decode("utf-8", "replace")
        evidence.append({"type": "http", "port": port, "status": response.status,
                         "server": headers.get("server", ""),
                         "title": _extract_title(body_text),
                         "location": headers.get("location", "")[:300]})
        if secure:
            sock = getattr(connection, "sock", None)
            if sock:
                cert = sock.getpeercert()
                cert_subject = _certificate_name(cert)
                if cert_subject:
                    evidence.append({"type": "tls_certificate", "port": port,
                                     "subject": cert_subject, "trusted": False})
    except (OSError, socket.timeout, ssl.SSLError, http.client.HTTPException, ValueError):
        pass
    finally:
        if connection:
            try:
                connection.close()
            except Exception:
                pass
    return {"port": port, "evidence": evidence, "headers": headers,
            "body": body_text[:_MAX_BODY], "certificate_subject": cert_subject}


def _extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()[:180] if match else ""


def _certificate_name(cert: dict) -> str:
    values = []
    for group in cert.get("subject", ()):
        for key, value in group:
            if key in ("commonName", "organizationName") and value:
                values.append(str(value))
    return " / ".join(dict.fromkeys(values))[:180]


def identify_router(host: str, network: str) -> dict:
    """Identify a gateway using bounded, unauthenticated HTTP/TLS metadata probes."""
    target = _private_target(host, network)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(_probe_http, target, port) for port in _PORTS]
        for future in concurrent.futures.as_completed(futures, timeout=4.5):
            try:
                result = future.result(timeout=0.1)
                if result["evidence"]:
                    results.append(result)
            except Exception:
                continue

    evidence = []
    text_parts = []
    open_ports = []
    for result in sorted(results, key=lambda item: item["port"]):
        open_ports.append(result["port"])
        evidence.extend(result["evidence"])
        text_parts.extend([
            result["headers"].get("server", ""),
            result["headers"].get("www-authenticate", ""),
            result["headers"].get("location", ""),
            result["certificate_subject"],
            result["body"],
        ])
    haystack = " ".join(text_parts).lower()
    matches = []
    for vendor, signatures in _VENDOR_PATTERNS:
        found = [signature for signature in signatures if signature in haystack]
        if found:
            matches.append({"vendor": vendor, "matched_signatures": found})
    distinct = list(dict.fromkeys(item["vendor"] for item in matches))
    if len(distinct) == 1:
        vendor, confidence = distinct[0], "MEDIUM"
        status = "IDENTIFIED_VENDOR"
    elif len(distinct) > 1:
        vendor, confidence = "Ambiguous", "LOW"
        status = "AMBIGUOUS"
    elif open_ports:
        vendor, confidence = "Unknown router / gateway web interface", "LOW"
        status = "WEB_INTERFACE_DETECTED"
    else:
        vendor, confidence = "Unknown", "NONE"
        status = "NO_WEB_MANAGEMENT_RESPONSE"

    adapters = {
        "MikroTik": ["MikroTik RouterOS 7+ HTTPS REST"],
        "TP-Link": ["TP-Link Omada Controller Open API (controller-managed deployments only)"],
        "Ubiquiti": ["UniFi Network API (supported UniFi consoles/controllers)"],
        "OpenWrt": ["OpenWrt ubus/rpcd (HTTPS or SSH; explicit enablement required)"],
        "ASUS": ["ASUSWRT model/firmware-specific integration (availability varies)"],
    }
    return {
        "host": target, "status": status, "vendor": vendor,
        "confidence": confidence, "open_management_ports": open_ports,
        "model": "", "firmware": "", "evidence": evidence,
        "vendor_matches": matches,
        "control_adapter_candidates": adapters.get(vendor, []),
        "control_ready": False,
        "control_message": (
            "Router identity is a preliminary fingerprint. Select and authenticate a compatible vendor adapter before any configuration change."
            if status != "NO_WEB_MANAGEMENT_RESPONSE" else
            "No web management response was observed. The router may use a non-standard port, a controller, SSH/SNMP, or block local probes."
        ),
        "probe_scope": "Authorised default gateway only",
        "credentials_sent": False,
        "configuration_changed": False,
    }
