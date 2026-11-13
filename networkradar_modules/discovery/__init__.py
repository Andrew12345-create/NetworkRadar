"""Network discovery adapters, parsers, probes and classification."""
from .adapters import (
    _is_real_mac, _norm_mac, _select_ipv4_interface_rows,
    _select_primary_adapter, _select_tshark_interface,
)
from .arp import parse_arp_output, read_arp_cache
from .classification import infer_type
from .nmap import best_os_match, parse_nmap_xml, run_nmap_discovery
from .probes import (
    is_same_private_http_host, netbios_name, reverse_dns, ssdp_scan,
)
from .mdns import build_ptr_query, discover_mdns, parse_mdns_packet

__all__ = [
    "_is_real_mac", "_norm_mac", "_select_ipv4_interface_rows",
    "_select_primary_adapter", "_select_tshark_interface",
    "parse_arp_output", "read_arp_cache", "infer_type",
    "best_os_match", "parse_nmap_xml", "run_nmap_discovery", "is_same_private_http_host",
    "netbios_name", "reverse_dns", "ssdp_scan",
    "build_ptr_query", "discover_mdns", "parse_mdns_packet",
]
