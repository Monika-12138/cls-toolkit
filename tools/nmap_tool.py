"""nmap —— 端口/服务扫描，解析 XML 输出为开放端口 findings。"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from .base import Tool


class NmapTool(Tool):
    id = "nmap"
    test = "PS-1"
    category = "PS"
    level = "L1"
    binary = "nmap"
    description = "扫描 DUT 开放端口与服务版本"
    requires = ["ip"]
    command_template = "nmap -sV -O -oX {evidence}.xml {ip}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        xml_path = Path(f"{evidence}.xml")
        if not xml_path.exists():
            return []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            return []

        findings: List[dict] = []
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                name = svc.get("name", "?") if svc is not None else "?"
                product = (svc.get("product", "") if svc is not None else "")
                version = (svc.get("version", "") if svc is not None else "")
                portid = port.get("portid", "?")
                proto = port.get("protocol", "?")
                detail = " ".join(p for p in (name, product, version) if p).strip()
                findings.append(
                    {
                        "severity": "info",
                        "title": f"开放端口 {portid}/{proto}",
                        "detail": detail or name,
                    }
                )
        return findings
