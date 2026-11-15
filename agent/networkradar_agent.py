"""Opt-in Windows hardware inventory agent for NetworkRadar.

This client is inventory-only. It does not execute remote commands, install a
service, alter system settings, or collect serial numbers unless explicitly
requested. Enrolment is single-use and TLS is pinned to the configured leaf
certificate SHA-256 fingerprint.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import getpass
import hmac
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

AGENT_VERSION = "1.0.0"
CAPABILITIES = ["inventory"]
_CONFIG_MAGIC = b"NRDPAPI1"
_MAX_RESPONSE = 65536


def normalise_certificate_pin(value: str) -> str:
    """Accept a SHA-256 hex fingerprint, optionally colon-separated by octet."""
    raw = str(value or "").strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:?){32}", raw):
        raise ValueError("Certificate pin must contain exactly 64 SHA-256 hex digits.")
    return raw.replace(":", "").lower()


def validate_server_url(value: str) -> tuple[str, int]:
    """Require an explicit HTTPS origin; path, credentials and query are rejected."""
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Agent server URL must be an https:// origin.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Server URL must not contain credentials, query or fragment.")
    if parsed.path not in ("", "/"):
        raise ValueError("Server URL must be an origin without a path.")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("Server URL contains an invalid port.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Server URL port is outside the valid range.")
    return parsed.hostname, port


def signature_payload(method: str, path: str, timestamp: str,
                      nonce: str, body: bytes) -> bytes:
    """Match the server's replay-resistant request-signature format exactly."""
    return "\\n".join([
        str(method).upper(), str(path), str(timestamp), str(nonce),
        hashlib.sha256(body).hexdigest(),
    ]).encode("utf-8")


def make_auth_headers(agent_id: str, auth_key: str, method: str,
                      path: str, body: bytes, *, timestamp: str | None = None,
                      nonce: str | None = None) -> dict[str, str]:
    """Create HMAC-SHA256 headers for one request body and path."""
    if not re.fullmatch(r"nr-[a-f0-9]{20}", str(agent_id or "")):
        raise ValueError("Invalid NetworkRadar agent ID.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(auth_key or "")):
        raise ValueError("Invalid per-agent authentication key.")
    ts = timestamp or str(int(time.time()))
    token = nonce or secrets.token_urlsafe(24)
    if not ts.isdigit() or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        raise ValueError("Invalid request timestamp or nonce.")
    digest = hmac.new(
        bytes.fromhex(auth_key),
        signature_payload(method, path, ts, token, body),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-NR-Agent": agent_id,
        "X-NR-Timestamp": ts,
        "X-NR-Nonce": token,
        "X-NR-Signature": digest,
    }


class PinnedHTTPSClient:
    """Minimal HTTPS client that checks the configured leaf certificate pin."""

    def __init__(self, server_url: str, certificate_pin: str, timeout: float = 10):
        self.host, self.port = validate_server_url(server_url)
        self.server_url = server_url.rstrip("/")
        self.pin = normalise_certificate_pin(certificate_pin)
        self.timeout = max(2.0, min(float(timeout), 30.0))

    def request(self, method: str, path: str, body: bytes = b"",
                headers: dict[str, str] | None = None) -> tuple[int, dict]:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("Agent API path must be an absolute path without query or fragment.")
        if len(body) > 65536:
            raise ValueError("Agent request body exceeds 64 KiB.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Trust is established by the explicit SHA-256 leaf-certificate pin below.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(
            self.host, self.port, context=context, timeout=self.timeout
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise ConnectionError("TLS socket was not established.")
            certificate = connection.sock.getpeercert(binary_form=True)
            actual_pin = hashlib.sha256(certificate or b"").hexdigest()
            if not certificate or not hmac.compare_digest(actual_pin, self.pin):
                raise ssl.SSLError(
                    "NetworkRadar server certificate pin mismatch; request was not sent."
                )
            request_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Connection": "close",
            }
            request_headers.update(headers or {})
            connection.request(method.upper(), path, body=body, headers=request_headers)
            response = connection.getresponse()
            raw = response.read(_MAX_RESPONSE + 1)
            if len(raw) > _MAX_RESPONSE:
                raise ValueError("NetworkRadar server response exceeded the size limit.")
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("NetworkRadar server returned invalid JSON.") from exc
            if not isinstance(payload, dict):
                raise ValueError("NetworkRadar server response must be a JSON object.")
            return response.status, payload
        finally:
            connection.close()


def _data_blob_type():
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]
    return DATA_BLOB


def _dpapi_transform(data: bytes, protect: bool) -> bytes:
    """Protect configuration with Windows DPAPI for the current Windows user."""
    if os.name != "nt":
        raise RuntimeError("The NetworkRadar endpoint agent stores secrets using Windows DPAPI.")
    blob_type = _data_blob_type()
    source_buffer = ctypes.create_string_buffer(data)
    source = blob_type(
        len(data),
        ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    target = blob_type()
    crypt32 = ctypes.WinDLL("Crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    blob_pointer = ctypes.POINTER(blob_type)
    crypt32.CryptProtectData.argtypes = [
        blob_pointer, ctypes.c_wchar_p, blob_pointer, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_ulong, blob_pointer,
    ]
    crypt32.CryptProtectData.restype = ctypes.c_int
    crypt32.CryptUnprotectData.argtypes = [
        blob_pointer, ctypes.POINTER(ctypes.c_wchar_p), blob_pointer,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, blob_pointer,
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    description = ctypes.c_wchar_p("NetworkRadar Agent configuration")
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(source), description, None, None, None, 0,
            ctypes.byref(target),
        )
    else:
        description_out = ctypes.c_wchar_p()
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(source), ctypes.byref(description_out), None, None,
            None, 0, ctypes.byref(target),
        )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(target.pbData, ctypes.c_void_p))


def save_config(config: dict, path: str | os.PathLike[str] | None = None) -> Path:
    """Persist credentials encrypted with current-user DPAPI, atomically."""
    destination = Path(path) if path else (
        Path(os.environ.get("LOCALAPPDATA") or Path.home()) /
        "NetworkRadar" / "agent.dat"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encrypted = _CONFIG_MAGIC + _dpapi_transform(raw, protect=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(encrypted)
    try:
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return destination


def load_config(path: str | os.PathLike[str] | None = None) -> dict:
    """Load and decrypt the current user's enrolled-agent configuration."""
    source = Path(path) if path else (
        Path(os.environ.get("LOCALAPPDATA") or Path.home()) /
        "NetworkRadar" / "agent.dat"
    )
    raw = source.read_bytes()
    if not raw.startswith(_CONFIG_MAGIC):
        raise ValueError("Agent configuration is not DPAPI-protected or is corrupt.")
    clear = _dpapi_transform(raw[len(_CONFIG_MAGIC):], protect=False)
    config = json.loads(clear.decode("utf-8"))
    if not isinstance(config, dict):
        raise ValueError("Agent configuration must be a JSON object.")
    normalise_certificate_pin(config.get("certificate_pin", ""))
    validate_server_url(config.get("server_url", ""))
    if not re.fullmatch(r"nr-[a-f0-9]{20}", str(config.get("agent_id", ""))):
        raise ValueError("Agent configuration has an invalid agent ID.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(config.get("auth_key", ""))):
        raise ValueError("Agent configuration has an invalid authentication key.")
    return config


def _run_powershell_inventory(include_serial: bool = False,
                              runner=subprocess.run) -> dict:
    """Collect read-only CIM inventory; serials are omitted unless opted in."""
    if os.name != "nt":
        raise RuntimeError("Hardware inventory collection currently requires Windows.")
    powershell = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
    script = r'''
$ErrorActionPreference = 'Stop'
$includeSerial = $env:NR_INCLUDE_SERIAL -eq '1'
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor | ForEach-Object {
    [ordered]@{
        name = $_.Name
        manufacturer = $_.Manufacturer
        cores = $_.NumberOfCores
        logical_processors = $_.NumberOfLogicalProcessors
        max_clock_mhz = $_.MaxClockSpeed
    }
})
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    [ordered]@{
        model = $_.Model
        manufacturer = $_.Manufacturer
        size_bytes = $_.Size
        interface_type = $_.InterfaceType
        media_type = $_.MediaType
        serial_number = $(if ($includeSerial) { $_.SerialNumber } else { '' })
    }
})
$adapters = @()
foreach ($adapter in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
    $cfg = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
    $ipv4 = @()
    $ipv6 = @()
    if ($cfg -and $cfg.IPv4Address) { $ipv4 = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress }) }
    if ($cfg -and $cfg.IPv6Address) { $ipv6 = @($cfg.IPv6Address | ForEach-Object { $_.IPAddress }) }
    $adapters += [ordered]@{
        name = $adapter.Name
        description = $adapter.InterfaceDescription
        mac = $adapter.MacAddress
        status = [string]$adapter.Status
        link_speed = $adapter.LinkSpeed
        ipv4 = $ipv4
        ipv6 = $ipv6
    }
}
$result = [ordered]@{
    hostname = $env:COMPUTERNAME
    manufacturer = $cs.Manufacturer
    model = $cs.Model
    system_family = $cs.SystemFamily
    system_type = $cs.SystemType
    total_memory_bytes = [int64]$cs.TotalPhysicalMemory
    cpu = $cpu
    bios = [ordered]@{
        vendor = $bios.Manufacturer
        version = $bios.SMBIOSBIOSVersion
        release_date = $bios.ReleaseDate
        serial_number = $(if ($includeSerial) { $bios.SerialNumber } else { '' })
    }
    operating_system = [ordered]@{
        caption = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
        install_date = $os.InstallDate
        last_boot = $os.LastBootUpTime
    }
    disks = $disks
    network_adapters = $adapters
    serial_numbers_included = $includeSerial
}
$result | ConvertTo-Json -Depth 7 -Compress
'''
    env = os.environ.copy()
    env["NR_INCLUDE_SERIAL"] = "1" if include_serial else "0"
    completed = runner(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
         "-Command", script],
        capture_output=True, text=True, timeout=30,
        encoding="utf-8", errors="replace", env=env,
    )
    if completed.returncode != 0:
        detail = re.sub(r"\s+", " ", completed.stderr or "PowerShell inventory failed")[:500]
        raise RuntimeError(detail)
    try:
        inventory = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid inventory JSON.") from exc
    if not isinstance(inventory, dict):
        raise RuntimeError("PowerShell inventory result was not an object.")
    return inventory


def collect_inventory(include_serial: bool = False, runner=subprocess.run) -> dict:
    """Build a bounded, versioned endpoint inventory payload."""
    inventory = _run_powershell_inventory(include_serial=include_serial, runner=runner)
    inventory["agent_version"] = AGENT_VERSION
    inventory["collected_at"] = datetime.now(timezone.utc).isoformat()
    inventory["platform"] = platform.platform()[:180]
    inventory["python_version"] = platform.python_version()
    inventory["hostname"] = str(inventory.get("hostname") or socket.gethostname())[:120]
    return inventory


def enrol(server_url: str, token: str, certificate_pin: str,
          *, timeout: float = 10) -> dict:
    """Use a single-use token to enrol; the server returns a per-agent HMAC key."""
    client = PinnedHTTPSClient(server_url, certificate_pin, timeout)
    payload = {
        "token": str(token),
        "hostname": socket.gethostname()[:120],
        "platform": platform.system() or "Windows",
        "os_version": platform.version()[:160],
        "agent_version": AGENT_VERSION,
        "capabilities": CAPABILITIES,
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    status, response = client.request("POST", "/agent/v1/enrol", body, {
        "Content-Type": "application/json",
    })
    if status != 201:
        raise RuntimeError(str(response.get("error") or f"Enrolment failed with HTTP {status}."))
    agent_id = str(response.get("agent_id") or "")
    auth_key = str(response.get("auth_key") or "")
    if not re.fullmatch(r"nr-[a-f0-9]{20}", agent_id):
        raise ValueError("Server returned an invalid agent ID.")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", auth_key):
        raise ValueError("Server returned an invalid per-agent authentication key.")
    return {
        "server_url": server_url.rstrip("/"),
        "certificate_pin": normalise_certificate_pin(certificate_pin),
        "agent_id": agent_id,
        "auth_key": auth_key.lower(),
        "interval_seconds": 300,
        "capabilities": CAPABILITIES,
    }


def report_inventory(config: dict, inventory: dict, *, timeout: float = 10) -> dict:
    """Send one signed inventory report over the pinned TLS channel."""
    client = PinnedHTTPSClient(
        config["server_url"], config["certificate_pin"], timeout
    )
    body = json.dumps(
        {"inventory": inventory}, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = make_auth_headers(
        config["agent_id"], config["auth_key"], "POST",
        "/agent/v1/report", body,
    )
    status, response = client.request(
        "POST", "/agent/v1/report", body, headers
    )
    if status != 200 or response.get("ok") is not True:
        raise RuntimeError(str(response.get("error") or f"Inventory report failed with HTTP {status}."))
    return response


def run_agent(config: dict, *, once: bool = False,
              include_serial: bool = False, interval: int | None = None) -> None:
    """Report inventory periodically; no command polling or remote execution."""
    delay = max(60, min(int(interval or config.get("interval_seconds", 300)), 3600))
    while True:
        try:
            inventory = collect_inventory(include_serial=include_serial)
            response = report_inventory(config, inventory)
            print(
                f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] "
                f"Inventory reported successfully ({response.get('server_time', 'server time unavailable')}).",
                flush=True,
            )
        except Exception as exc:
            print(f"NetworkRadar agent report failed: {str(exc)[:300]}", file=sys.stderr, flush=True)
        if once:
            return
        time.sleep(delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Opt-in, inventory-only NetworkRadar Windows endpoint agent."
    )
    parser.add_argument("--enrol", action="store_true",
                        help="Enrol this endpoint using a single-use NetworkRadar token.")
    parser.add_argument("--server", help="HTTPS origin of the NetworkRadar agent hub.")
    parser.add_argument("--token", help="Single-use enrolment token (not saved).")
    parser.add_argument("--server-cert-sha256",
                        help="SHA-256 fingerprint of the server's TLS leaf certificate.")
    parser.add_argument("--config", help="Encrypted DPAPI configuration file path.")
    parser.add_argument("--once", action="store_true",
                        help="Collect and report once, then exit.")
    parser.add_argument("--interval", type=int, default=None,
                        help="Report interval in seconds (60–3600; default 300).")
    parser.add_argument("--include-serial", action="store_true",
                        help="Explicitly include BIOS and disk serial numbers in reports.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.enrol:
            if not (args.server and args.server_cert_sha256):
                raise ValueError("--enrol requires --server and --server-cert-sha256.")
            token = args.token or getpass.getpass("Single-use NetworkRadar enrolment token: ")
            if not token.strip():
                raise ValueError("An enrolment token is required.")
            config = enrol(args.server, token.strip(), args.server_cert_sha256)
            path = save_config(config, args.config)
            print(f"Endpoint enrolled. Encrypted agent configuration saved to: {path}")
        else:
            config = load_config(args.config)
        run_agent(
            config, once=args.once, include_serial=args.include_serial,
            interval=args.interval,
        )
        return 0
    except KeyboardInterrupt:
        print("NetworkRadar endpoint agent stopped.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"NetworkRadar endpoint agent error: {str(exc)[:400]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
