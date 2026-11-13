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
    try:
        parsed = urllib.parse.urlparse(url)
        target = parsed.hostname
        if not target:
            return False
        target_ip = ipaddress.ip_address(target)
        source = ipaddress.ip_address(source_ip)
        return (
            target_ip == source
            and target_ip.is_private
            and parsed.scheme.lower() == "http"
        )
    except (ValueError, TypeError):
        return False


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


def ssdp_scan(timeout: float = 2.0, *, app_version: str = "12.0.3") -> dict:
    found = {}
    message = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.25)
    try:
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.monotonic() + max(0.0, float(timeout))
        while time.monotonic() < deadline:
            try:
                packet, address = sock.recvfrom(8192)
            except socket.timeout:
                continue
            ip = address[0]
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
                    xml = response.read(256 * 1024)
                root = ET.fromstring(xml)
                for element in root.iter():
                    tag = element.tag.split("}")[-1].lower()
                    value = _clean_text(element.text or "")
                    if tag in (
                        "friendlyname", "manufacturer", "modelname",
                        "modelnumber", "devicetype", "serialnumber",
                    ):
                        metadata[tag] = value
            except Exception:
                pass
            found[ip] = metadata
    finally:
        sock.close()
    return found
