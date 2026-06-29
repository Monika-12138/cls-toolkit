"""RouterSploit -- router/IoT auto vuln probing; grab "is vulnerable" lines from stdout.

RouterSploit (autopwn / scanners) prints per module:
  [+] 192.168.1.1:80 http exploits/routers/.../rce is vulnerable
  [-] ...                                              is not vulnerable
Take lines that contain "is vulnerable" but not "not vulnerable"; each one is a
matched known-vuln module (high).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_VULN_RE = re.compile(r"^\s*\[\+\]\s*(.+?)\s+is vulnerable\s*$", re.IGNORECASE)


class RoutersploitTool(Tool):
    id = "routersploit"
    test = "PS-2"
    category = "PS"
    level = "L1"
    binary = "routersploit"
    description = "Automated router/IoT known-vuln probing"
    requires = ["ip"]
    command_template = "routersploit --execute 'use scanners/autopwn; set target {ip}; run'"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            if re.search(r"not vulnerable", line, re.IGNORECASE):
                continue
            m = _VULN_RE.match(line)
            if not m:
                continue
            target = m.group(1).strip()
            if target in seen:
                continue
            seen.add(target)
            findings.append(
                {
                    "severity": "high",
                    "title": "Matched known-vuln module",
                    "detail": target,
                }
            )

        if not findings and re.search(r"\bis vulnerable\b", raw, re.IGNORECASE):
            findings.append(
                {
                    "severity": "high",
                    "title": "RouterSploit: exploitable vulnerability detected",
                    "detail": "see evidence log (could not parse the specific module)",
                }
            )
        return findings
