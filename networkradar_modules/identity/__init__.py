"""Device identity and evidence fusion components."""

from .dhcp import analyse_dhcp_identity, parse_parameter_request_list
from .fingerprints import derive_identity, dhcp_fingerprint, mac_properties, normalise_mac
from .oui import lookup_ieee_assignment, parse_ieee_registry
from .recognition import recognition_family_compatible
from .quality import assess_identity_quality
from .protocols import analyse_mdns_services, parse_ssdp_message
from .investigation import build_identity_next_steps

__all__ = [
    "analyse_dhcp_identity", "parse_parameter_request_list",
    "derive_identity", "dhcp_fingerprint", "mac_properties", "normalise_mac",
    "lookup_ieee_assignment", "parse_ieee_registry", "recognition_family_compatible",
    "analyse_mdns_services", "parse_ssdp_message",
    "assess_identity_quality", "build_identity_next_steps",
]
