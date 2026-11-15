"""Local ARP cache collection and parsing."""
from __future__ import annotations

import re
import subprocess
from typing import Callable


_ARP_ROW = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
)


def parse_arp_output(output: str) -> dict[str, str]:
    """Parse IPv4-to-MAC rows from Windows and compatible arp -a output."""
    mapping = {}
    for line in str(output or "").splitlines():
        match = _ARP_ROW.search(line)
        if match:
            mapping[match.group(1)] = match.group(2).replace("-", ":").upper()
    return mapping


def read_arp_cache(
    *,
    runner: Callable = subprocess.run,
    timeout: float = 8,
) -> dict[str, str]:
    """Read the local ARP table; return an empty map when the OS command fails."""
    try:
        result = runner(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return parse_arp_output(result.stdout or "")
    except Exception:
        return {}
