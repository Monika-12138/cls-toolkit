"""XSSer —— 跨站脚本检测，从 stdout 的最终统计判断是否存在 XSS 注入点。

XSSer 没有稳定机读 JSON，结论在 stdout 末尾的统计块：
  [*] Final Results:
  - Injections: 5
  - Failed: 4
  - Successful: 1
  - Accuracy: 20 %
`Successful: N` 且 N>0 → 存在可注入点（high）。另抓 `[I]` 行里列出的具体 URL。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_SUCCESS_RE = re.compile(r"Successful:\s*(\d+)", re.IGNORECASE)
# XSSer 报告里列出的可注入 URL / payload 行
_VULN_URL_RE = re.compile(r"\[I\]\s*(?:Vulnerable|Target|URL)[^:]*:\s*(\S+)", re.IGNORECASE)


class XsserTool(Tool):
    id = "xsser"
    test = "CP-6"
    category = "CP"
    level = "L1"
    binary = "xsser"
    description = "跨站脚本 XSS 检测"
    requires = ["portal_url"]
    command_template = "xsser --url {portal_url}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []

        successful = 0
        for m in _SUCCESS_RE.finditer(raw):
            successful = max(successful, int(m.group(1)))

        if successful > 0:
            urls = [m.group(1) for m in _VULN_URL_RE.finditer(raw)]
            detail = (
                "可注入 URL: " + ", ".join(dict.fromkeys(urls))
                if urls
                else f"XSSer 报告 {successful} 处成功注入"
            )
            findings.append(
                {
                    "severity": "high",
                    "title": f"XSS 注入点 ({successful} 处)",
                    "detail": detail,
                }
            )
            return findings

        # 兜底：统计块没解析到，但 stdout 明确提示 XSS
        if re.search(r"XSS\s*FOUND|is vulnerable|vulnerable to XSS", raw, re.IGNORECASE):
            findings.append(
                {
                    "severity": "high",
                    "title": "XSS 注入: 检测到可注入点",
                    "detail": "详见 evidence 日志（未能解析出成功计数）",
                }
            )
        return findings
