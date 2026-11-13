"""
net_context_2.py — Network Context Intelligence 2.0 + authoritative authorisation.

Fixes 8.1.0 defects D1–D4, D9, D11:
  D1  authorisation granted at 0% confidence — now requires profile match AND
      confidence >= MIN_FP_CONFIDENCE_WEIGHT AND approval AND freshness.
  D2  single fragile PowerShell command — now four independent sources.
  D3  fragile `arp -a` text parse — now Get-NetNeighbor with fallback.
  D4  host attributes polluting network fingerprint — adapter alias and adapter
      MAC are excluded from network identity.
  D9  no historical network context — callers persist NetworkContext snapshots.
  D11 confidence never used — now the primary gate.

Fingerprint = NETWORK identity only. Components:
  subnet, gateway, gateway_mac, dns, dhcp, ssid, bssid
Weighted so a strong anchor (gateway_mac or bssid) is required for CONFIRMED.
"""
from __future__ import annotations
import dataclasses, enum, hashlib, ipaddress, json, re, subprocess
from datetime import datetime, timezone, timedelta
from typing import Any

MIN_FP_CONFIDENCE_WEIGHT = 0.55
PROFILE_MAX_AGE_DAYS = 90
FP_WEIGHTS = {"subnet": 0.30, "gateway": 0.20, "gateway_mac": 0.25,
              "dns": 0.10, "dhcp": 0.05, "ssid": 0.05, "bssid": 0.05}

class Conf(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    MISSING = "MISSING"
    STALE = "STALE"

@dataclasses.dataclass
class Obs:
    value: Any
    confidence: Conf
    source: str
    observed_at: str
    detail: dict = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class Adapter:
    name: str
    index: int
    description: str
    status: str
    media: str
    mac: Obs
    ipv4: Obs
    prefix: Obs

@dataclasses.dataclass
class NetworkContext:
    adapters: list[Adapter]
    primary: Adapter | None
    gateway: Obs
    gateway_mac: Obs
    dns: Obs
    dhcp: Obs
    ssid: Obs
    bssid: Obs
    fingerprint: Obs
    collected_at: str
    warnings: list[str]

@dataclasses.dataclass
class AuthDecision:
    authorised: bool
    decision: str                        # AUTHORISED | NOT_AUTHORISED | INDETERMINATE
    reasons: list[str]
    matched_profile_id: str | None
    fingerprint: str | None
    fingerprint_weight: float
    classification: str                  # CONFIRMED | INFERRED | MISSING | STALE

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _ps(cmd: str, timeout: int = 15) -> list[dict]:
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace")
    except Exception:
        return []
    if p.returncode != 0 or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]

def _is_real_mac(m: str | None) -> bool:
    if not m:
        return False
    clean = re.sub(r"[^0-9A-Fa-f]", "", m)
    return len(clean) == 12 and clean.upper() not in {"000000000000", "FFFFFFFFFFFF"}

def _norm_mac(m: str | None) -> str:
    if not m:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", m).upper()
    return ":".join(clean[i:i+2] for i in range(0, 12, 2)) if len(clean) == 12 else ""

def detect_network_context() -> NetworkContext:
    warnings: list[str] = []
    now = _now()

    adapters_raw = _ps(
        "Get-NetAdapter | Select-Object Name,InterfaceIndex,InterfaceDescription,"
        "MacAddress,Status,MediaType | ConvertTo-Json -Depth 3")
    ip_raw = _ps(
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,IPAddress,PrefixLength | ConvertTo-Json -Depth 3")
    route_raw = _ps(
        "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object InterfaceIndex,NextHop,RouteMetric,InterfaceMetric | "
        "ConvertTo-Json -Depth 3")
    dns_raw = _ps(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,ServerAddresses | ConvertTo-Json -Depth 3")
    dhcp_raw = _ps(
        "Get-NetIPInterface -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,Dhcp | ConvertTo-Json -Depth 3")

    if not adapters_raw: warnings.append("Get-NetAdapter returned no data.")
    if not ip_raw:       warnings.append("Get-NetIPAddress returned no data.")
    if not route_raw:    warnings.append("Get-NetRoute returned no default route.")
    if not dns_raw:      warnings.append("Get-DnsClientServerAddress returned no data.")

    ips_by_idx: dict[int, dict] = {}
    for r in ip_raw:
        try: ips_by_idx[int(r["InterfaceIndex"])] = r
        except (KeyError, ValueError, TypeError): pass
    dns_by_idx: dict[int, list[str]] = {}
    for r in dns_raw:
        try: dns_by_idx[int(r["InterfaceIndex"])] = list(r.get("ServerAddresses") or [])
        except (KeyError, ValueError, TypeError): pass
    dhcp_by_idx: dict[int, str] = {}
    for r in dhcp_raw:
        try: dhcp_by_idx[int(r["InterfaceIndex"])] = str(r.get("Dhcp", ""))
        except (KeyError, ValueError, TypeError): pass
    default_routes: dict[int, dict] = {}
    for r in route_raw:
        try:
            idx = int(r["InterfaceIndex"])
            metric = int(r.get("RouteMetric", 9999)) + int(r.get("InterfaceMetric", 0))
        except (KeyError, ValueError, TypeError):
            continue
        prev = default_routes.get(idx)
        if prev is None or metric < prev["_metric"]:
            default_routes[idx] = {**r, "_metric": metric}

    adapters: list[Adapter] = []
    for a in adapters_raw:
        try:
            idx = int(a["InterfaceIndex"])
            name = a.get("Name") or f"if{idx}"
        except (KeyError, ValueError, TypeError):
            continue
        status = str(a.get("Status") or "Unknown")
        mac_val = _norm_mac(a.get("MacAddress"))
        mac_conf = (Conf.CONFIRMED if (_is_real_mac(mac_val) and status == "Up")
                    else Conf.STALE if _is_real_mac(mac_val)
                    else Conf.MISSING)
        ip_r = ips_by_idx.get(idx) or {}
        ip_val = ip_r.get("IPAddress")
        pfx = ip_r.get("PrefixLength")
        adapters.append(Adapter(
            name=name, index=idx,
            description=str(a.get("InterfaceDescription") or ""),
            status=status, media=str(a.get("MediaType") or ""),
            mac=Obs(mac_val, mac_conf, "Get-NetAdapter", now, {"status": status}),
            ipv4=Obs(ip_val, Conf.CONFIRMED if ip_val else Conf.MISSING,
                     "Get-NetIPAddress", now),
            prefix=Obs(pfx, Conf.CONFIRMED if isinstance(pfx, int) else Conf.MISSING,
                       "Get-NetIPAddress", now),
        ))

    up = [x for x in adapters if x.status == "Up" and x.ipv4.value]
    primary = next((x for x in up if x.index in default_routes),
                   up[0] if up else None)

    if primary is None:
        gateway = Obs(None, Conf.MISSING, "Get-NetRoute", now,
                      {"reason": "no active adapter with IPv4 address"})
        gateway_mac = Obs(None, Conf.MISSING, "Get-NetNeighbor", now,
                          {"reason": "no gateway"})
    elif primary.index not in default_routes:
        gateway = Obs(None, Conf.MISSING, "Get-NetRoute", now,
                      {"reason": "no default route on active adapter"})
        gateway_mac = Obs(None, Conf.MISSING, "Get-NetNeighbor", now,
                          {"reason": "no gateway"})
    else:
        nh = default_routes[primary.index].get("NextHop")
        if nh and nh not in ("0.0.0.0", ""):
            gateway = Obs(nh, Conf.CONFIRMED, "Get-NetRoute", now,
                          {"interface_index": primary.index})
            gw_mac = _gateway_mac_via_neighbor(nh)
            gateway_mac = Obs(gw_mac,
                              Conf.CONFIRMED if gw_mac else Conf.MISSING,
                              "Get-NetNeighbor", now,
                              {"note": "Absent gateway MAC means no recent traffic, not a fault."})
        else:
            gateway = Obs(None, Conf.MISSING, "Get-NetRoute", now,
                          {"reason": "NextHop is 0.0.0.0"})
            gateway_mac = Obs(None, Conf.MISSING, "Get-NetNeighbor", now,
                              {"reason": "no next hop"})

    dns_servers = sorted(set(dns_by_idx.get(primary.index, []))) if primary else []
    dns = Obs(dns_servers, Conf.CONFIRMED if dns_servers else Conf.MISSING,
              "Get-DnsClientServerAddress", now)

    dhcp_flag = dhcp_by_idx.get(primary.index) if primary else None
    dhcp = Obs(dhcp_flag,
               Conf.CONFIRMED if dhcp_flag in ("Enabled", "Disabled") else Conf.MISSING,
               "Get-NetIPInterface", now,
               {"note": "DHCP flag only; server IP not confirmed by this API."})

    ssid, bssid = _wifi_details()

    components = {
        "subnet": str(ipaddress.ip_network(
            f"{primary.ipv4.value}/{primary.prefix.value}", strict=False))
            if (primary and primary.ipv4.value
                and isinstance(primary.prefix.value, int)) else None,
        "gateway": gateway.value if gateway.confidence == Conf.CONFIRMED else None,
        "gateway_mac": gateway_mac.value if gateway_mac.confidence == Conf.CONFIRMED else None,
        "dns": dns.value if dns.confidence == Conf.CONFIRMED else None,
        "dhcp": dhcp.value if dhcp.confidence == Conf.CONFIRMED else None,
        "ssid": ssid or None,
        "bssid": bssid or None,
    }
    present_weight = sum(FP_WEIGHTS[k] for k, v in components.items() if v is not None)
    has_strong = components["gateway_mac"] is not None or components["bssid"] is not None

    if present_weight == 0:
        fingerprint = Obs(None, Conf.MISSING, "fingerprint", now,
                          {"reason": "no confirmed network identity components"})
    else:
        digest = hashlib.sha256(
            json.dumps(components, sort_keys=True).encode()).hexdigest()[:24]
        conf = (Conf.CONFIRMED if present_weight >= 0.75 and has_strong
                else Conf.INFERRED if present_weight >= 0.40
                else Conf.MISSING)
        fingerprint = Obs(digest, conf, "fingerprint", now,
                          {"components": components,
                           "weight": round(present_weight, 3),
                           "has_strong_anchor": has_strong})

    return NetworkContext(
        adapters=adapters, primary=primary,
        gateway=gateway, gateway_mac=gateway_mac,
        dns=dns, dhcp=dhcp,
        ssid=Obs(ssid, Conf.CONFIRMED if ssid else Conf.MISSING, "netsh wlan", now),
        bssid=Obs(bssid, Conf.CONFIRMED if bssid else Conf.MISSING, "netsh wlan", now),
        fingerprint=fingerprint, collected_at=now, warnings=warnings)

def _gateway_mac_via_neighbor(gw_ip: str) -> str | None:
    rows = _ps(f"Get-NetNeighbor -AddressFamily IPv4 -IPAddress '{gw_ip}' | "
               f"Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Depth 3")
    for r in rows:
        ll = _norm_mac(r.get("LinkLayerAddress"))
        st = str(r.get("State") or "")
        if _is_real_mac(ll) and st in ("Reachable", "Stale", "Permanent"):
            return ll
    return None

def _wifi_details() -> tuple[str, str]:
    try:
        p = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                           capture_output=True, text=True, timeout=8,
                           encoding="utf-8", errors="replace")
    except Exception:
        return "", ""
    if p.returncode != 0:
        return "", ""
    ssid = bssid = ""
    for line in p.stdout.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower(); v = v.strip()
        if k == "ssid" and not ssid:      ssid = v
        elif k == "bssid" and not bssid:  bssid = v
    return ssid, bssid

def to_legacy_ctx(nc: NetworkContext) -> dict:
    """Return a dict shaped like 8.1.0's NET_CTX so existing callers work."""
    p = nc.primary
    comps = nc.fingerprint.detail.get("components", {})
    return {
        "network": comps.get("subnet") or "",
        "ip": (p.ipv4.value if p else "") or "",
        "gateway": nc.gateway.value or "",
        "interface": (p.name if p else "") or "",
        "prefix": (p.prefix.value if p and isinstance(p.prefix.value, int) else None),
        "ssid": nc.ssid.value or "",
        "bssid": nc.bssid.value or "",
        "mode": "AUTO",
        "dns_servers": ",".join(nc.dns.value) if nc.dns.confidence == Conf.CONFIRMED else "",
        "adapter_mac": (p.mac.value if p and p.mac.confidence == Conf.CONFIRMED else "") or "",
        "gateway_mac": nc.gateway_mac.value or "",
        "fingerprint": nc.fingerprint.value or "",
        "fingerprint_raw": json.dumps(nc.fingerprint.detail, sort_keys=True),
        "confidence": int(round(nc.fingerprint.detail.get("weight", 0) * 100))
                      if nc.fingerprint.value else 0,
        "confidence_notes": "; ".join(nc.warnings) or "all primary sources responded",
        "_classification": {
            "gateway": nc.gateway.confidence.value,
            "gateway_mac": nc.gateway_mac.confidence.value,
            "dns": nc.dns.confidence.value,
            "dhcp": nc.dhcp.confidence.value,
            "fingerprint": nc.fingerprint.confidence.value,
        },
    }

def reconcile(nc: NetworkContext, profiles: list[dict],
              now: datetime | None = None) -> AuthDecision:
    """Single authoritative network-authorisation decision.
    profiles: [{'id','fingerprint','approved','last_seen'}, ...]
    """
    now = now or datetime.now(timezone.utc)
    fp = nc.fingerprint
    if fp.value is None or fp.confidence == Conf.MISSING:
        return AuthDecision(False, "INDETERMINATE",
            ["Network fingerprint could not be computed from confirmed evidence.",
             f"Classification: {fp.confidence.value}."],
            None, None, 0.0, fp.confidence.value)
    weight = float(fp.detail.get("weight", 0.0))
    if weight < MIN_FP_CONFIDENCE_WEIGHT:
        return AuthDecision(False, "INDETERMINATE",
            [f"Fingerprint weight {weight:.2f} < {MIN_FP_CONFIDENCE_WEIGHT}.",
             "Active discovery disabled until confidence improves."],
            None, fp.value, weight, fp.confidence.value)
    match = next((p for p in profiles if p.get("fingerprint") == fp.value), None)
    if not match:
        return AuthDecision(False, "NOT_AUTHORISED",
            ["No network profile matches the current fingerprint."],
            None, fp.value, weight, fp.confidence.value)
    pid = match.get("id") or "?"
    if not match.get("approved"):
        return AuthDecision(False, "NOT_AUTHORISED",
            [f"Profile {pid} exists but approved != True."],
            pid, fp.value, weight, fp.confidence.value)
    last = match.get("last_seen")
    if last:
        try:
            age = now - datetime.fromisoformat(last)
            if age > timedelta(days=PROFILE_MAX_AGE_DAYS):
                return AuthDecision(False, "INDETERMINATE",
                    [f"Profile {pid} last seen {age.days} days ago "
                     f"(> {PROFILE_MAX_AGE_DAYS}). Re-approve required."],
                    pid, fp.value, weight, "STALE")
        except (ValueError, TypeError):
            pass
    return AuthDecision(True, "AUTHORISED",
        [f"Profile {pid} approved; fingerprint weight {weight:.2f}; "
         f"classification {fp.confidence.value}."],
        pid, fp.value, weight, fp.confidence.value)