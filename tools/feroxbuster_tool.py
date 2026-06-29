"""feroxbuster -- high-performance directory/file enumeration; parse --json
(ndjson) output into found-path findings.

With --json, feroxbuster writes one JSON object per line (newline-delimited JSON):
  {"type":"response","url":"http://x/admin","status":200,"content_length":1234,...}
  {"type":"statistics",...}                # summary line, ignored
Only type==response lines are taken. Paths matching sensitive keywords -> low,
others -> info (same convention as dirsearch).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .base import Tool

# same sensitive-path keywords as dirsearch (admin / backup / source leak / creds)
_SENSITIVE = (
    "admin", "login", "config", "backup", "bak", "sql", "db",
    "passwd", "password", "secret", "private", "key", "token",
    ".git", ".env", ".svn", "phpinfo", "setup", "install", "console",
    "debug", "test", "tmp", "upload", "shell",
)


class FeroxbusterTool(Tool):
    id = "feroxbuster"
    test = "CP-1"
    category = "CP"
    level = "L1"
    binary = "feroxbuster"
    description = "High-performance directory/file enumeration"
    requires = ["portal_url"]
    # -w is required, otherwise feroxbuster errors out immediately. dirb's
    # common.txt ships with Kali and is a safe default; point this at a bigger
    # list (e.g. seclists raft-*-directories.txt) if you want more coverage.
    command_template = (
        "feroxbuster -u {portal_url} -w /usr/share/wordlists/dirb/common.txt "
        "--json --output {evidence}.json"
    )

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        json_path = Path(f"{evidence}.json")
        text = (
            json_path.read_text(encoding="utf-8", errors="replace")
            if json_path.exists()
            else raw
        )

        findings: List[dict] = []
        seen: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("type") != "response":
                continue
            url = str(obj.get("url") or "")
            if not url or url in seen:
                continue
            seen.add(url)
            status = obj.get("status", "?")
            length = obj.get("content_length", "")
            sensitive = any(k in url.lower() for k in _SENSITIVE)
            detail = f"HTTP {status}" + (f", {length} bytes" if length != "" else "")
            findings.append(
                {
                    "severity": "low" if sensitive else "info",
                    "title": f"Found path {url}",
                    "detail": detail,
                }
            )
        return findings
