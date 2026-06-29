"""testssl.sh -- TLS/SSL config check; parse risky entries from JSON output."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .base import Tool

_RISK = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class TestsslTool(Tool):
    id = "testssl"
    test = "CO-3"
    category = "CO"
    level = "L1"
    binary = "testssl.sh"
    description = "Check TLS config and protocol weaknesses of the portal/cloud endpoint"
    requires = ["portal_url"]
    command_template = "testssl.sh --quiet --jsonfile {evidence}.json {portal_url}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        json_path = Path(f"{evidence}.json")
        if not json_path.exists():
            return []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        findings: List[dict] = []
        for item in data if isinstance(data, list) else []:
            sev = str(item.get("severity", "")).upper()
            if sev in _RISK:
                findings.append(
                    {
                        "severity": sev.lower(),
                        "title": item.get("id", ""),
                        "detail": item.get("finding", ""),
                    }
                )
        return findings
