"""commix -- command injection check; extract command-injection verdicts from stdout.

commix likewise has no stable JSON; the verdict is in stdout:
  - "The (GET) 'id' parameter is vulnerable to ... command injection"
  - "the back-end operating system is Linux"
Parse raw stdout for these markers.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

# commix's vuln line: parameter name and injection type are in quotes / parens
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
    description = "Command injection check on the config portal"
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
                    "title": f"Command injection: {where}parameter {param}",
                    "detail": kind,
                }
            )
        for m in _OS_RE.finditer(raw):
            findings.append(
                {
                    "severity": "info",
                    "title": "Back-end OS identified",
                    "detail": m.group(1),
                }
            )

        if not findings and re.search(
            r"vulnerable to .*command injection|injection point", raw, re.IGNORECASE
        ):
            findings.append(
                {
                    "severity": "high",
                    "title": "Command injection: injectable point detected",
                    "detail": "see evidence log (could not parse the specific parameter)",
                }
            )
        return findings
