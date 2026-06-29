"""netdiscover -- LAN live-host discovery; parse the host table into findings.

netdiscover -P prints a parsable table, one host per line:
     192.168.1.1     aa:bb:cc:dd:ee:ff      3      180  Realtek Semiconductor Corp.
Columns: IP / MAC / Count / Len / MAC Vendor (vendor may contain spaces).
Interactive-mode "Unique Hosts" data rows also start with an IP, so the same
regex handles both.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_HOST_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"      # IP
    r"([0-9a-fA-F:]{17})\s+"                  # MAC
    r"\d+\s+\d+\s+"                           # Count / Len
    r"(.*\S)?\s*$"                            # Vendor (may be empty)
)


class NetdiscoverTool(Tool):
    id = "netdiscover"
    test = "PS-1"
    category = "PS"
    level = "L1"
    binary = "netdiscover"
    description = "Discover live hosts on the LAN"
    requires = ["lan_subnet"]
    command_template = "netdiscover -P -r {lan_subnet}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            m = _HOST_RE.match(line)
            if not m:
                continue
            ip, mac, vendor = m.group(1), m.group(2), (m.group(3) or "").strip()
            if ip in seen:
                continue
            seen.add(ip)
            detail = f"MAC {mac}" + (f" / {vendor}" if vendor else "")
            findings.append(
                {
                    "severity": "info",
                    "title": f"Live host {ip}",
                    "detail": detail,
                }
            )
        return findings
