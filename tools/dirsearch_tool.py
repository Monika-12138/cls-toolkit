"""dirsearch -- brute-force hidden paths/admin interfaces on the config portal;
parse the JSON report into found-path findings.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .base import Tool

# paths matching these keywords deserve more attention (admin / backup / source
# leak / credentials)
_SENSITIVE = (
    "admin", "login", "config", "backup", "bak", "sql", "db",
    "passwd", "password", "secret", "private", "key", "token",
    ".git", ".env", ".svn", "phpinfo", "setup", "install", "console",
    "debug", "test", "tmp", "upload", "shell",
)


class DirsearchTool(Tool):
    id = "dirsearch"
    test = "CP-1"
    category = "CP"
    level = "L1"
    binary = "dirsearch"
    description = "Brute-force hidden paths/admin interfaces on the config portal"
    requires = ["portal_url"]
    command_template = "dirsearch -u {portal_url} --format json -o {evidence}.json"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        json_path = Path(f"{evidence}.json")
        if not json_path.exists():
            return []
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        findings: List[dict] = []
        for entry in _iter_results(data):
            url = str(entry.get("url") or entry.get("path") or "")
            if not url:
                continue
            status = entry.get("status") or entry.get("status-code") or "?"
            length = (
                entry.get("content-length")
                or entry.get("contentLength")
                or entry.get("length")
                or ""
            )
            low = url.lower()
            sensitive = any(k in low for k in _SENSITIVE)
            detail = f"HTTP {status}" + (f", {length} bytes" if length != "" else "")
            findings.append(
                {
                    "severity": "low" if sensitive else "info",
                    "title": f"Found path {url}",
                    "detail": detail,
                }
            )
        return findings


def _iter_results(data) -> List[dict]:
    """Handle several dirsearch JSON shapes:
      - {"results": [ {...}, ... ]}
      - {"<target-url>": [ {...}, ... ]}  (older builds group by target)
      - [ {...}, ... ]
    """
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return [r for r in data["results"] if isinstance(r, dict)]
        out: List[dict] = []
        for value in data.values():
            if isinstance(value, list):
                out.extend(r for r in value if isinstance(r, dict))
        return out
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []
