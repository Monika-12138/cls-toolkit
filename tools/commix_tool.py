"""commix —— 命令注入检测，从 stdout 提取命令注入结论 findings。

commix 同样没有稳定 JSON，结论在 stdout：
  - "The (GET) 'id' parameter is vulnerable to ... command injection"
  - "the back-end operating system is Linux"
解析 raw 抓这些 marker。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

# commix 的漏洞行，参数名与注入类型在引号 / 括号里
_VULN_RE = re.compile(
    r"the\s*\(([^)]*)\)\s*'?([^'\s]+)'?\s*parameter is vulnerable to (.+?command injection)",
    re.IGNORECASE,
)
_OS_RE = re.compile(r"back-end operating system is\s*(.+?)\s*$", re.IGNORECASE)


class CommixTool(Tool):
    id = "commix"
    test = "CP-4"
    category = "CP"
    level = "L1"
    binary = "commix"
    description = "配置门户命令注入检测"
    requires = ["portal_url"]
    command_template = "commix --url={portal_url} --batch"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        for m in _VULN_RE.finditer(raw):
            method, param, kind = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
            where = f"{method} " if method else ""
            findings.append(
                {
                    "severity": "high",
                    "title": f"命令注入: {where}参数 {param}",
                    "detail": kind,
                }
            )
        for m in _OS_RE.finditer(raw):
            findings.append(
                {
                    "severity": "info",
                    "title": "后端操作系统识别",
                    "detail": m.group(1),
                }
            )

        if not findings and re.search(
            r"vulnerable to .*command injection|injection point", raw, re.IGNORECASE
        ):
            findings.append(
                {
                    "severity": "high",
                    "title": "命令注入: 检测到可注入点",
                    "detail": "详见 evidence 日志（未能解析出具体参数）",
                }
            )
        return findings
