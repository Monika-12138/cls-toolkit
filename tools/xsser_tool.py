"""XSSer -- cross-site scripting detection; decide from the stdout final stats
whether an XSS injection point exists.

XSSer has no stable machine-readable JSON; the verdict is in the stats block at
the end of stdout:
  [*] Final Results:
  - Injections: 5
  - Failed: 4
  - Successful: 1
  - Accuracy: 20 %
`Successful: N` with N>0 -> injectable point exists (high). Also grab any specific
URLs listed in `[I]` lines.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_SUCCESS_RE = re.compile(r"Successful:\s*(\d+)", re.IGNORECASE)
# injectable URL / payload lines listed in XSSer's report
_VULN_URL_RE = re.compile(r"\[I\]\s*(?:Vulnerable|Target|URL)[^:]*:\s*(\S+)", re.IGNORECASE)


class XsserTool(Tool):
    id = "xsser"
    test = "CP-6"
    category = "CP"
    level = "L1"
    binary = "xsser"
    description = "Cross-site scripting (XSS) detection"
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
                "injectable URLs: " + ", ".join(dict.fromkeys(urls))
                if urls
                else f"XSSer reported {successful} successful injection(s)"
            )
            findings.append(
                {
                    "severity": "high",
                    "title": f"XSS injection point ({successful} found)",
                    "detail": detail,
                }
            )
            return findings

        # fallback: stats block not parsed, but stdout clearly flags XSS
        if re.search(r"XSS\s*FOUND|is vulnerable|vulnerable to XSS", raw, re.IGNORECASE):
            findings.append(
                {
                    "severity": "high",
                    "title": "XSS injection: injectable point detected",
                    "detail": "see evidence log (could not parse the success count)",
                }
            )
        return findings
