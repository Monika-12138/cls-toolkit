"""sqlmap -- SQL injection check on config-portal parameters; extract injection
points / DBMS findings from stdout.

sqlmap has no stable machine-readable JSON; the injection verdict is mainly in
stdout:
  - "Parameter: id (GET)"            injected parameter
  - "Type: boolean-based blind"      injection type
  - "sqlmap identified the following injection point"
  - "back-end DBMS: MySQL"           back-end database
So we parse raw stdout, grabbing these markers line by line.
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
    description = "SQL injection check on config-portal parameters"
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
                detail = "; ".join(types) if types else "injectable parameter present"
                findings.append(
                    {
                        "severity": "high",
                        "title": f"SQL injection: parameter {current_param}",
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
                    "title": "Back-end DBMS identified",
                    "detail": m.group(1),
                }
            )

        # no structured parameter parsed, but stdout clearly states injection -> one fallback
        if not findings and re.search(
            r"is vulnerable|injection point|appears to be injectable", raw, re.IGNORECASE
        ):
            findings.append(
                {
                    "severity": "high",
                    "title": "SQL injection: injectable point detected",
                    "detail": "see evidence log (could not parse the specific parameter)",
                }
            )
        return findings
