"""Bounded active mDNS/DNS-SD discovery for authorised local networks.

The collector sends standard DNS-SD PTR questions to the IPv4 mDNS multicast
group and requests unicast replies (QU). It never follows advertised URLs,
downloads device descriptions, or treats service names as confirmed models.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time
from collections import defaultdict
from typing import Any

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
SERVICE_TYPES = (
    "_services._dns-sd._udp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_smb._tcp.local",
    "_device-info._tcp.local",
    "_workstation._tcp.local",
    "_hap._tcp.local",
    "_home-assistant._tcp.local",
    "_sonos._tcp.local",
    "_ssh._tcp.local",
    "_spotify-connect._tcp.local",
)
_TYPE_NAMES = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV"}


def _encode_name(name: str) -> bytes:
    labels = str(name).rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError("invalid DNS label")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_ptr_query(service: str) -> bytes:
    """Build one mDNS PTR question, setting QU to request a unicast reply."""
    return (struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
            + _encode_name(service)
            + struct.pack("!HH", 12, 0x8001))


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset = None
    visited: set[int] = set()
    for _ in range(128):
        if cursor >= len(packet):
            raise ValueError("DNS name exceeds packet")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet) or pointer in visited:
                raise ValueError("invalid DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label encoding")
        cursor += 1
        if length == 0:
            return ".".join(labels), next_offset if next_offset is not None else cursor
        if length > 63 or cursor + length > len(packet):
            raise ValueError("invalid DNS label length")
        labels.append(packet[cursor:cursor + length].decode("utf-8", "replace"))
        cursor += length
    raise ValueError("DNS compression depth exceeded")


def parse_mdns_packet(packet: bytes) -> list[dict[str, Any]]:
    """Parse bounded PTR/SRV/TXT/A/AAAA records from an mDNS response."""
    if not isinstance(packet, (bytes, bytearray)) or len(packet) < 12 or len(packet) > 9000:
        return []
    try:
        _ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
        if not flags & 0x8000:
            return []
        total = qd + an + ns + ar
        if total > 256:
            return []
        offset = 12
        for _ in range(qd):
            _name, offset = _read_name(packet, offset)
            if offset + 4 > len(packet):
                return []
            offset += 4
        records: list[dict[str, Any]] = []
        for _ in range(an + ns + ar):
            name, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                return records
            rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            end = offset + rdlength
            if end > len(packet):
                return records
            value: Any = None
            if rtype == 1 and rdlength == 4:
                value = socket.inet_ntop(socket.AF_INET, packet[offset:end])
            elif rtype == 28 and rdlength == 16:
                value = socket.inet_ntop(socket.AF_INET6, packet[offset:end])
            elif rtype in (12, 33):
                if rtype == 12:
                    value, _ = _read_name(packet, offset)
                elif rdlength >= 7:
                    priority, weight, port = struct.unpack_from("!HHH", packet, offset)
                    target, _ = _read_name(packet, offset + 6)
                    value = {"priority": priority, "weight": weight,
                             "port": port, "target": target}
            elif rtype == 16:
                chunks = []
                pos = offset
                while pos < end:
                    size = packet[pos]
                    pos += 1
                    if pos + size > end:
                        break
                    chunks.append(packet[pos:pos + size].decode("utf-8", "replace"))
                    pos += size
                value = chunks
            if value is not None:
                records.append({
                    "name": name.lower(), "type": _TYPE_NAMES.get(rtype, str(rtype)),
                    "value": value, "ttl": int(ttl),
                    "cache_flush": bool(rclass & 0x8000),
                })
            offset = end
        return records
    except (ValueError, OSError, struct.error, UnicodeError):
        return []


def discover_mdns(
    *,
    duration: float = 2.5,
    interface_ip: str = "",
    max_packets: int = 256,
    services: tuple[str, ...] = SERVICE_TYPES,
) -> list[dict[str, Any]]:
    """Send rate-bounded DNS-SD browse questions and return per-source records.

    The optional interface_ip must be a literal local IPv4 address. The caller
    should invoke this only after the application's network-approval check.
    """
    try:
        duration = max(0.25, min(float(duration), 5.0))
        max_packets = max(1, min(int(max_packets), 512))
        bind_ip = str(interface_ip or "0.0.0.0")
        if bind_ip != "0.0.0.0":
            parsed = ipaddress.ip_address(bind_ip)
            if parsed.version != 4 or not parsed.is_private:
                return []
    except (TypeError, ValueError):
        return []

    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"ip": "", "records": set(), "record_details": []}
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        if bind_ip != "0.0.0.0":
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(bind_ip))
        sock.bind((bind_ip, 0))
        sock.settimeout(0.10)
        # A small, deterministic query set avoids flooding the LAN.
        for service in tuple(services)[:len(SERVICE_TYPES)]:
            try:
                sock.sendto(build_ptr_query(service), (MDNS_GROUP, MDNS_PORT))
            except (OSError, ValueError):
                continue
        deadline = time.monotonic() + duration
        received = 0
        while time.monotonic() < deadline and received < max_packets:
            try:
                packet, address = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            received += 1
            source_ip = address[0]
            try:
                parsed_source = ipaddress.ip_address(source_ip)
                if parsed_source.version != 4 or not parsed_source.is_private:
                    continue
            except ValueError:
                continue
            records = parse_mdns_packet(packet)
            if not records:
                continue
            item = grouped[source_ip]
            item["ip"] = source_ip
            for record in records:
                value = record["value"]
                if isinstance(value, dict):
                    value_text = f'{value.get("target", "")}:{value.get("port", "")}'
                elif isinstance(value, list):
                    value_text = " ".join(value)
                else:
                    value_text = str(value)
                summary = f'{record["type"]} {record["name"]} -> {value_text}'[:500]
                item["records"].add(summary)
                if len(item["record_details"]) < 64:
                    item["record_details"].append(record)
    finally:
        sock.close()

    results = []
    for ip in sorted(grouped):
        item = grouped[ip]
        results.append({
            "ip": ip,
            "records": " | ".join(sorted(item["records"]))[:2000],
            "record_details": item["record_details"],
            "source": "active mDNS/DNS-SD",
        })
    return results
