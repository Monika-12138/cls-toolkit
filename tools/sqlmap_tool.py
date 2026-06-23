"""sqlmap —— 配置门户参数 SQL 注入检测，从 stdout 提取注入点 / DBMS findings。

sqlmap 没有稳定的机读 JSON，注入结论主要在 stdout：
  - "Parameter: id (GET)"            注入参数
  - "Type: boolean-based blind"      注入类型
  - "sqlmap identified the following injection point"
  - "back-end DBMS: MySQL"           后端数据库
所以解析 raw stdout，逐行抓这些 marker。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_PARAM_RE = re.compile(r"^\s*Parameter:\s*(.+?)\s*$")
_TYPE_RE = re.compile(r"^\s*Type:\s*(.+?)\s*$")
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+?)\s*$", re.IGNORECASE)


class SqlmapTool(Tool):
    id = "sqlmap"
    test = "CP-3"
    category = "CP"
    level = "L1"
    binary = "sqlmap"
    description = "配置门户参数 SQL 注入检测"
    requires = ["portal_url"]
    command_template = (
        "sqlmap -u {portal_url} --batch --crawl=1 --risk=1 --level=2 "
        "--output-dir={evidence}"
    )

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        current_param = None
        types: List[str] = []

        def flush():
            if current_param:
                detail = "; ".join(types) if types else "存在可注入参数"
                findings.append(
                    {
                        "severity": "high",
                        "title": f"SQL 注入: 参数 {current_param}",
                        "detail": detail,
                    }
                )

        for line in raw.splitlines():
            m = _PARAM_RE.match(line)
            if m:
                flush()
                current_param = m.group(1)
                types = []
                continue
            m = _TYPE_RE.match(line)
            if m and current_param:
                types.append(m.group(1))
                continue
        flush()

        for m in _DBMS_RE.finditer(raw):
            findings.append(
                {
                    "severity": "info",
                    "title": "后端数据库识别",
                    "detail": m.group(1),
                }
            )

        # 没抓到结构化参数，但 stdout 明确说有注入 → 兜底报一条
        if not findings and re.search(
            r"is vulnerable|injection point|appears to be injectable", raw, re.IGNORECASE
        ):
            findings.append(
                {
                    "severity": "high",
                    "title": "SQL 注入: 检测到可注入点",
                    "detail": "详见 evidence 日志（未能解析出具体参数）",
                }
            )
        return findings
