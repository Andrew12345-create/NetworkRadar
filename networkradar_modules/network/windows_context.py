"""Fast, bounded Windows network-context collection and native fallback parsing."""
from __future__ import annotations

import ipaddress
import re


def build_network_context_script() -> str:
    """Collect the five network-context datasets in one PowerShell process."""
    return (
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "$a=@(Get-NetAdapter -ErrorAction Stop | Select-Object Name,InterfaceIndex,"
        "InterfaceDescription,InterfaceGuid,MacAddress,Status,MediaType); "
        "$i=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | "
        "Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressState,SkipAsSource); "
        "$r=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction Stop | Select-Object InterfaceIndex,NextHop,RouteMetric,InterfaceMetric); "
        "$d=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | "
        "Select-Object InterfaceIndex,ServerAddresses); "
        "$h=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | "
        "Select-Object InterfaceIndex,Dhcp); "
        "[pscustomobject]@{adapters=$a;addresses=$i;routes=$r;dns=$d;dhcp=$h} | "
        "ConvertTo-Json -Depth 6 -Compress"
    )


def parse_ipconfig_all(output: str) -> dict:
    """Parse English Windows ipconfig /all output without guessing missing fields.

    Returns the same five dataset keys used by the PowerShell collector. If
    output is localised or lacks usable IPv4 data, the relevant arrays are empty.
    """
    text = str(output or "")
    headers = list(re.finditer(
        r"(?im)^\s*([^\r\n]*?\badapter\s+[^:\r\n]+):\s*$", text
    ))
    adapters, addresses, routes, dns_rows, dhcp_rows = [], [], [], [], []
    for index, match in enumerate(headers, start=1):
        end = headers[index].start() if index < len(headers) else len(text)
        block = text[match.end():end]
        title = match.group(1).strip()
        name_match = re.search(r"(?i)\badapter\s+(.+)$", title)
        name = name_match.group(1).strip() if name_match else title

        def field(label: str) -> str:
            found = re.search(
                rf"(?im)^\s*{label}[ .]*:\s*([^\r\n]*)", block
            )
            return found.group(1).strip() if found else ""

        ipv4_match = re.search(
            r"(?im)^\s*IPv4 Address[ .]*:\s*([0-9.]+)", block
        )
        mask = field("Subnet Mask")
        ipv4 = ipv4_match.group(1) if ipv4_match else ""
        try:
            address = ipaddress.ip_address(ipv4)
            network = ipaddress.ip_network(f"{address}/{mask}", strict=False)
            if address.version != 4 or address.is_loopback or address.is_link_local or address.is_unspecified:
                continue
            prefix = network.prefixlen
        except ValueError:
            continue

        mac = field("Physical Address")
        mac = mac.replace("-", ":").upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            mac = ""

        gateway_match = re.search(
            r"(?im)^\s*Default Gateway[ .]*:\s*([0-9.]+)", block
        )
        gateway = gateway_match.group(1) if gateway_match else ""
        try:
            if gateway and ipaddress.ip_address(gateway).version != 4:
                gateway = ""
        except ValueError:
            gateway = ""

        dns_match = re.search(
            r"(?ims)^\s*DNS Servers[ .]*:\s*([^\r\n]*(?:\r?\n[ \t]+[0-9.]+)*)",
            block,
        )
        dns_values = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                                dns_match.group(1)) if dns_match else []
        dhcp_text = field("DHCP Enabled").casefold()
        dhcp_value = "Enabled" if dhcp_text in {"yes", "true"} else (
            "Disabled" if dhcp_text in {"no", "false"} else ""
        )

        adapters.append({
            "Name": name, "InterfaceIndex": index,
            "InterfaceDescription": "", "InterfaceGuid": "",
            "MacAddress": mac, "Status": "Up", "MediaType": "",
            "_native_fallback": True,
        })
        addresses.append({
            "InterfaceIndex": index, "IPAddress": str(address),
            "PrefixLength": prefix, "AddressState": "Preferred",
            "SkipAsSource": False,
        })
        if gateway:
            routes.append({
                "InterfaceIndex": index, "NextHop": gateway,
                "RouteMetric": 100, "InterfaceMetric": 0,
            })
        dns_rows.append({"InterfaceIndex": index, "ServerAddresses": dns_values})
        dhcp_rows.append({"InterfaceIndex": index, "Dhcp": dhcp_value})

    return {
        "adapters": adapters, "addresses": addresses, "routes": routes,
        "dns": dns_rows, "dhcp": dhcp_rows,
    }
