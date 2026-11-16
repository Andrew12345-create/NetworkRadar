"""Windows neighbour-table discovery for active local-network observations."""
from __future__ import annotations
import ipaddress, json, os, re, subprocess
from typing import Callable

_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")

def _valid_mac(value):
    mac=str(value or "").strip().replace("-",":").upper()
    if not _MAC.fullmatch(mac): return ""
    octets=[int(part,16) for part in mac.split(":")]
    if (octets[0]&1) or all(x==0 for x in octets) or all(x==255 for x in octets): return ""
    return mac

def parse_windows_neighbor_rows(payload, network, *, reachable_only=True, interface_index=None):
    """Parse Get-NetNeighbor JSON, scoped to IPv4 and fresh Reachable state."""
    try:
        scope=ipaddress.ip_network(str(network),strict=False)
        if scope.version!=4: return []
    except (TypeError,ValueError): return []
    try: data=json.loads(payload) if isinstance(payload,(str,bytes,bytearray)) else payload
    except (TypeError,ValueError,UnicodeDecodeError): return []
    if isinstance(data,dict): data=[data]
    if not isinstance(data,list): return []
    records=[]; seen=set()
    for item in data:
        if not isinstance(item,dict): continue
        try:
            address=ipaddress.ip_address(str(item.get("IPAddress") or "").strip())
            if address.version!=4 or address not in scope or address.is_loopback or address.is_multicast or address.is_unspecified: continue
            state=str(item.get("State") or "").strip()
            if reachable_only and state.casefold()!="reachable": continue
            mac=_valid_mac(item.get("LinkLayerAddress"))
            if not mac: continue
            try: idx=int(item.get("InterfaceIndex",item.get("ifIndex",0)) or 0)
            except (TypeError,ValueError): idx=0
            if interface_index is not None and idx != int(interface_index): continue
        except (TypeError,ValueError): continue
        key=(str(address),mac,idx)
        if key in seen: continue
        seen.add(key)
        records.append({"ip":str(address),"mac":mac,"state":state,"interface_index":idx,
                        "mac_locally_administered":bool(int(mac[:2],16)&2),
                        "source":"Windows Get-NetNeighbor"})
    return records

def collect_windows_neighbor_cache(network, *, runner:Callable=subprocess.run,
                                   platform=None, timeout=12, interface_index=None):
    """Read the Windows IPv4 neighbour table without sending network probes."""
    windows=os.name=="nt" if platform is None else str(platform).casefold() in {"nt","windows"}
    if not windows:
        return {"status":"UNAVAILABLE","records":[],"detail":"Windows neighbour-table collection is only available on Windows."}
    try: ipaddress.ip_network(str(network),strict=False)
    except (TypeError,ValueError):
        return {"status":"ERROR","records":[],"detail":"Invalid IPv4 network scope."}
    try:
        selected_index = int(interface_index) if interface_index is not None else None
    except (TypeError, ValueError):
        selected_index = None
    filter_clause = (f" | Where-Object {{ $_.InterfaceIndex -eq {selected_index} }}"
                     if selected_index is not None else "")
    script=("$ErrorActionPreference='Stop'; Get-NetNeighbor -AddressFamily IPv4 "
            "-ErrorAction Stop" + filter_clause +
            " | Select-Object IPAddress,LinkLayerAddress,State,InterfaceIndex | ConvertTo-Json -Compress")
    try:
        result=runner(["powershell.exe","-NoProfile","-Command",script],
                      capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout)
    except Exception as exc:
        return {"status":"ERROR","records":[],"detail":str(exc)[:240]}
    if getattr(result,"returncode",1)!=0:
        return {"status":"ERROR","records":[],"detail":str(getattr(result,"stderr","") or "Get-NetNeighbor failed.")[-240:]}
    records=parse_windows_neighbor_rows(
        getattr(result,"stdout","") or "", network, interface_index=selected_index
    )
    return {"status":"ONLINE" if records else "ONLINE_EMPTY","records":records,
            "detail":f"{len(records)} Reachable neighbour(s) in {network}."}

def merge_reachable_neighbors(devices, records):
    """Merge Reachable observations; never overwrite conflicting MAC evidence."""
    merged=list(devices or [])
    by_ip={str(row.get("ip") or ""):row for row in merged if row.get("ip")}
    for record in records or []:
        ip=str(record.get("ip") or ""); mac=_valid_mac(record.get("mac"))
        if not ip or not mac or str(record.get("state") or "").casefold()!="reachable": continue
        local=bool(record.get("mac_locally_administered"))
        note=("Locally administered MAC observed; may be randomized or locally assigned. It is not a stable factory identity."
              if local else "Globally administered MAC observed; OUI is not proof of device model.")
        observation=f"Reachable neighbour on interface {record.get('interface_index',0)}; MAC={mac}. {note}"
        existing=by_ip.get(ip)
        if existing is not None:
            current=_valid_mac(existing.get("mac"))
            if not current: existing["mac"]=mac
            elif current!=mac:
                observation=f"Neighbour-table MAC {mac} conflicts with scan MAC {current}; scan MAC retained and no identity merge made."
            existing.setdefault("_extra",[]).append(("Windows neighbour cache",observation,65 if current in ("",mac) else 25))
            existing.setdefault("discovery_sources",[]).append("Windows neighbour cache")
            continue
        item={"ip":ip,"mac":mac,"vendor":"Unknown","hostname":"-","device_name":"",
              "friendly_name":"","device_type":"Unclassified device","os_guess":"Unknown",
              "model":"","identification_confidence":0,"identification_methods":"",
              "open_ports":"","service_summary":"","discovery_sources":["Windows neighbour cache"],
              "discovery_reason":"Get-NetNeighbor state=Reachable",
              "_extra":[("Windows neighbour cache",observation,65)]}
        merged.append(item); by_ip[ip]=item
    return merged
