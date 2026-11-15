"""Evidence-based device-family classification helpers."""
from __future__ import annotations

import re


def infer_type(device, ssdp=None, *, gateway_ip=""):
    ssdp = ssdp or {}
    text = " ".join(str(x or "") for x in (
        device.get("device_name", ""), device.get("hostname", ""),
        device.get("friendly_name", ""), device.get("model", ""),
        device.get("service_summary", ""), device.get("os_guess", ""),
        ssdp.get("devicetype", ""), ssdp.get("friendlyname", ""),
        ssdp.get("manufacturer", ""), ssdp.get("modelname", ""),
        " ".join(device.get("services_found", []) or []),
        " ".join(x.get("banner", "") for x in device.get("service_intel", []) or [])
    )).lower()
    ports = set(device.get("port_numbers", []) or [])
    if device.get("_is_gateway") or (gateway_ip and device.get("ip") == gateway_ip):
        return "Router / network gateway (role-confirmed)"
    patterns = [
        (r"\b(printer|laserjet|deskjet|epson|brother|canon|xerox|ricoh|kyocera|ipp)\b", "Printer (probable)"),
        (r"\b(ipcam|camera|cctv|hikvision|dahua|axis communications|rtsp)\b", "IP camera / video (probable)"),
        (r"\b(iphone|ipad|ipod|ios device)\b", "Apple mobile (probable)"),
        (r"\b(macbook|imac|mac mini|mac studio)\b", "Apple computer (probable)"),
        (r"\b(android|galaxy|pixel|oneplus|xiaomi|redmi|oppo|vivo|huawei phone)\b", "Android/mobile device (probable)"),
        (r"\b(windows|win10|win11|desktop-|laptop|thinkpad|elitebook|latitude|optiplex|probook)\b", "Computer (probable)"),
        (r"\b(xbox|playstation|ps[345]|nintendo|switch console)\b", "Gaming console (probable)"),
        (r"\b(chromecast|google tv|fire tv|roku|smart.?tv|mediarenderer|airplay receiver|webos tv|tizen)\b", "Smart TV / streaming (probable)"),
        (r"\b(synology|qnap|truenas|freenas|nas[0-9-]|network attached storage)\b", "NAS / storage (probable)"),
        (r"\b(mikrotik|routeros|openwrt|opnsense|pfsense|unifi|ubiquiti|access.?point|wireless controller|switch[0-9-])\b", "Router / switch / access point (probable)"),
        (r"\b(asterisk|yealink|polycom|grandstream|voip|sip phone)\b", "VoIP / IP phone (probable)"),
        (r"\b(esxi|vmware|hyper-v|proxmox|xenserver|virtual machine)\b", "Virtualisation host (probable)"),
        (r"\b(server|windows server|ubuntu server|debian|rhel|centos|almalinux|rocky linux)\b", "Server (probable)"),
        (r"\b(sonos|bose|echo dot|echo show|homepod|smart speaker)\b", "Smart speaker / audio (probable)"),
        (r"\b(thermostat|smart plug|zigbee|zwave|tasmota|shelly|tuya|home assistant)\b", "Smart-home / IoT device (probable)"),
        (r"\b(ups|apc smart|eaton power|powerware)\b", "UPS / power equipment (probable)"),
        (r"\b(doorbell|intercom|access control|biometric|badge reader)\b", "Access control / intercom (probable)"),
        (r"\b(nvr|dvr|video recorder|surveillance recorder)\b", "Video surveillance recorder (probable)"),
        (r"\b(air.?condition|refrigerator|washing machine|dishwasher|oven|smart appliance)\b", "Smart appliance (probable)"),
    ]
    for pattern, category in patterns:
        if re.search(pattern, text, re.I):
            return category
    if ports & {9100, 631, 515}:
        return "Device exposing printing service (type unconfirmed)"
    if ports & {554, 8554, 10554}:
        return "Device exposing RTSP/video service (type unconfirmed)"
    if ports & {8008, 8009, 32400, 1900}:
        return "Device exposing media/UPnP service (type unconfirmed)"
    if ports & {161, 162}:
        return "Device exposing SNMP service (type unconfirmed)"
    if 3389 in ports or ({445, 139} <= ports):
        return "Device exposing Windows remote/file services (type unconfirmed)"
    if ports & {22, 80, 443, 445, 3389}:
        return "Network service host (type unconfirmed)"
    return "Unclassified network device"


