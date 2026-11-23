"""Local-network name and UPnP/SSDP discovery probes.

SSDP description URLs are restricted to the responding private IPv4/IPv6
address. Redirects are revalidated so a device cannot redirect the fetch to
another host or an unrelated internal service.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Callable


def _clean_text(value, limit=180):
    value = re.sub(r"[\x00-\x1f\x7f]", " ", str(value or ""))
    return re.sub(r"\s+", " ", value).strip()[:limit]


def is_same_private_http_host(source_ip: str, url: str) -> bool:
    """Accept only literal-IP HTTP URLs served by the SSDP responder itself."""
    try:
        parsed = urllib.parse.urlparse(url)
        target = parsed.hostname
        if (not target or parsed.username or parsed.password
                or parsed.fragment or parsed.scheme.lower() != "http"):
            return False
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            return False
        target_ip = ipaddress.ip_address(target)
        source = ipaddress.ip_address(source_ip)
        return target_ip == source and target_ip.is_private
    except (ValueError, TypeError):
        return False


def parse_upnp_description(xml_bytes: bytes) -> dict:
    """Parse a bounded UPnP description; advertised fields remain unverified."""
    if not isinstance(xml_bytes, (bytes, bytearray)):
        raise TypeError("UPnP description must be bytes")
    if len(xml_bytes) > 256 * 1024:
        raise ValueError("UPnP description exceeds 256 KiB")
    upper = bytes(xml_bytes).upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("DTD and entity declarations are not allowed")
    root = ET.fromstring(xml_bytes)

    def local_name(tag):
        return str(tag).split("}")[-1].casefold()

    def text_of(element, name):
        # Only inspect direct children so a nested device cannot donate its
        # model/manufacturer to a parent device that did not advertise it.
        for child in element:
            if local_name(child.tag) == name:
                value = _clean_text(child.text or "", 240)
                if value:
                    return value
        return ""

    devices = [node for node in root.iter() if local_name(node.tag) == "device"]
    if not devices:
        return {}
    fields = (
        "friendlyname", "manufacturer", "manufacturerurl", "modelname",
        "modelnumber", "modelurl", "devicetype", "serialnumber", "udn",
        "upc", "presentationurl",
    )
    result = {key: text_of(devices[0], key) for key in fields}
    result["embedded_devices"] = [
        {
            key: text_of(node, key)
            for key in ("friendlyname", "manufacturer", "modelname",
                        "modelnumber", "devicetype", "udn")
        }
        for node in devices[1:]
    ]
    result["embedded_devices"] = [
        item for item in result["embedded_devices"] if any(item.values())
    ][:32]
    return result


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject SSDP redirects that leave the responding private host."""

    def __init__(self, source_ip: str):
        super().__init__()
        self.source_ip = source_ip

    def redirect_request(self, request, fp, code, message, headers, new_url):
        resolved = urllib.parse.urljoin(request.full_url, new_url)
        if not is_same_private_http_host(self.source_ip, resolved):
            raise urllib.error.HTTPError(
                resolved, code, "SSDP redirect rejected: destination is not "
                "the same private responding host", headers, fp
            )
        return super().redirect_request(
            request, fp, code, message, headers, resolved
        )


def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        name = _clean_text(name.rstrip("."))
        if name and name != ip:
            return name
    except (OSError, socket.timeout):
        pass
    return ""


def netbios_name(
    ip: str,
    *,
    runner: Callable = subprocess.run,
) -> str:
    try:
        result = runner(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        for line in (result.stdout or "").splitlines():
            match = re.match(
                r"^\s*([^\s]+)\s+<([0-9A-Fa-f]{2})>\s+(UNIQUE|GROUP)",
                line,
            )
            if (match and match.group(2).upper() == "00"
                    and match.group(3).upper() == "UNIQUE"):
                candidate = _clean_text(match.group(1))
                if candidate and candidate.upper() not in ("WORKGROUP", "IS~"):
                    return candidate
    except Exception:
        pass
    return ""


def ssdp_scan(
    timeout: float = 2.0,
    *,
    app_version: str = "12.0.3",
    interface_ip: str = "",
    allowed_network: str = "",
) -> dict:
    """Discover UPnP devices only on the explicitly selected private subnet.

    The caller must supply the selected adapter address and approved network.
    Multicast is bound to that adapter, and responders outside that subnet are
    discarded before any advertised description URL is fetched.
    """
    try:
        local_ip = ipaddress.ip_address(str(interface_ip or "").strip())
        network = ipaddress.ip_network(str(allowed_network or "").strip(), strict=False)
        timeout = max(0.25, min(float(timeout), 5.0))
        if (
            local_ip.version != 4
            or network.version != 4
            or not local_ip.is_private
            or not network.is_private
            or local_ip not in network
        ):
            return {}
    except (TypeError, ValueError, OverflowError):
        return {}

    found = {}
    message = (
        "M-SEARCH * HTTP/1.1\\r\\nHOST: 239.255.255.250:1900\\r\\n"
        'MAN: "ssdp:discover"\\r\\nMX: 2\\r\\nST: ssdp:all\\r\\n\\r\\n'
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
            socket.inet_aton(str(local_ip)),
        )
        sock.bind((str(local_ip), 0))
        sock.settimeout(0.25)
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout
        responses = 0
        while time.monotonic() < deadline and responses < 64:
            try:
                packet, address = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            responses += 1
            try:
                responder = ipaddress.ip_address(address[0])
            except (ValueError, TypeError):
                continue
            if responder.version != 4 or responder not in network:
                continue
            ip = str(responder)
            headers = {}
            for line in packet.decode("utf-8", errors="replace").splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            location = headers.get("location", "")
            if not location or not is_same_private_http_host(ip, location):
                continue
            metadata = {
                "ssdp_server": _clean_text(headers.get("server", "")),
                "usn": _clean_text(headers.get("usn", "")),
            }
            try:
                request = urllib.request.Request(
                    location,
                    headers={"User-Agent": f"NR/{app_version}"},
                )
                opener = urllib.request.build_opener(
                    _SameHostRedirectHandler(ip)
                )
                with opener.open(request, timeout=2) as response:
                    xml = response.read(256 * 1024 + 1)
                metadata.update(parse_upnp_description(xml))
            except Exception:
                pass
            found[ip] = metadata
    finally:
        sock.close()
    return found
