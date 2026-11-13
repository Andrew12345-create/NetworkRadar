"""Network discovery adapters and parsers."""
from .nmap import parse_nmap_xml, run_nmap_discovery

__all__ = ["parse_nmap_xml", "run_nmap_discovery"]
