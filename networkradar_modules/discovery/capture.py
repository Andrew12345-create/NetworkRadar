"""Resolve DHCP fields against the installed TShark registry."""
from __future__ import annotations

DHCP_CAPTURE_FIELDS=("frame.time_epoch","ip.src","ip.dst","dhcp.option.dhcp",
"dhcp.hw.mac_addr","dhcp.ip.your","dhcp.option.hostname","dhcp.option.dhcp_server_id",
"dhcp.option.requested_ip_address","dhcp.option.router","dhcp.option.domain_name_server",
"dhcp.option.subnet_mask","dhcp.option.lease_time","dhcp.option.vendor_class_id",
"dhcp.option.request_list_item","dhcp.option.client_id",
"dhcp.option.client_system_architecture","dhcp.option.user_class.text","dhcp.fqdn.name")
_REQUIRED=frozenset({"frame.time_epoch","ip.src","ip.dst","dhcp.option.dhcp","dhcp.hw.mac_addr","dhcp.ip.your"})
_ALIASES={
"dhcp.option.dhcp":("bootp.option.dhcp",),"dhcp.hw.mac_addr":("bootp.hw.mac_addr",),
"dhcp.ip.your":("bootp.ip.your",),"dhcp.option.hostname":("bootp.option.hostname",),
"dhcp.option.dhcp_server_id":("bootp.option.dhcp_server_id",),
"dhcp.option.requested_ip_address":("bootp.option.requested_ip_address",),
"dhcp.option.router":("bootp.option.router",),
"dhcp.option.domain_name_server":("bootp.option.domain_name_server",),
"dhcp.option.subnet_mask":("bootp.option.subnet_mask",),
"dhcp.option.lease_time":("bootp.option.lease_time",),
"dhcp.option.vendor_class_id":("bootp.option.vendor_class_id",),
"dhcp.option.request_list_item":("bootp.option.request_list_item",),
"dhcp.option.client_id":("bootp.option.client_id",),
"dhcp.option.client_system_architecture":("bootp.option.client_system_architecture",),
"dhcp.option.user_class.text":("bootp.option.user_class.text",),
"dhcp.fqdn.name":("bootp.fqdn.name",)}

def parse_tshark_field_registry(text):
    """Extract field abbreviations from TShark -G fields output."""
    found=set()
    for line in str(text or "").splitlines():
        if not line.startswith("F\t"): continue
        columns=line.split("\t")
        if len(columns)>=3 and columns[2].strip(): found.add(columns[2].strip())
    return found

def resolve_tshark_fields(registry_text, requested_fields=DHCP_CAPTURE_FIELDS):
    """Resolve logical DHCP fields; optional omissions preserve column positions."""
    available=parse_tshark_field_registry(registry_text)
    selected=[]; missing_required=[]; missing_optional=[]
    for logical in requested_fields:
        actual=next((candidate for candidate in (logical,*_ALIASES.get(logical,()))
                     if candidate in available),"")
        if actual: selected.append((logical,actual))
        elif logical in _REQUIRED: missing_required.append(logical)
        else: missing_optional.append(logical)
    return {"fields":selected,"missing_required":missing_required,
            "missing_optional":missing_optional,"available_count":len(available)}
