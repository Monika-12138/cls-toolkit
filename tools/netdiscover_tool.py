"""netdiscover —— 局域网存活主机发现，解析输出表格为主机清单 findings。

netdiscover -P 的可解析输出每行一台主机：
     192.168.1.1     aa:bb:cc:dd:ee:ff      3      180  Realtek Semiconductor Corp.
列：IP / MAC / Count / Len / MAC Vendor（厂商名可能含空格）。
交互模式的 "Unique Hosts" 表格数据行同样以 IP 开头，用同一正则即可。
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
    r"(.*\S)?\s*$"                            # Vendor（可空）
)


class NetdiscoverTool(Tool):
    id = "netdiscover"
    test = "PS-1"
    category = "PS"
    level = "L1"
    binary = "netdiscover"
    description = "发现局域网内存活主机"
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
            detail = f"MAC {mac}" + (f" · {vendor}" if vendor else "")
            findings.append(
                {
                    "severity": "info",
                    "title": f"存活主机 {ip}",
                    "detail": detail,
                }
            )
        return findings
