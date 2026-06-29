"""RouterSploit —— 路由器/IoT 漏洞自动探测，从 stdout 抓 "is vulnerable" 结论。

RouterSploit (autopwn / scanners) 对每个模块打印：
  [+] 192.168.1.1:80 http exploits/routers/.../rce is vulnerable
  [-] ...                                              is not vulnerable
抓含 "is vulnerable" 但不含 "not vulnerable" 的行，每条 = 命中一个已知漏洞模块（high）。
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
    description = "路由器/IoT 常见漏洞自动探测"
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
                    "title": "命中已知漏洞模块",
                    "detail": target,
                }
            )

        if not findings and re.search(r"\bis vulnerable\b", raw, re.IGNORECASE):
            findings.append(
                {
                    "severity": "high",
                    "title": "RouterSploit: 检测到可利用漏洞",
                    "detail": "详见 evidence 日志（未能解析出具体模块）",
                }
            )
        return findings
