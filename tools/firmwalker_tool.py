"""firmwalker -- scan an extracted firmware filesystem for keys/passwords/hidden
accounts; parse the output text into hit findings.

firmwalker writes results in a structure like:
    ***Search for password files***
    #####################################passwd
    /etc/passwd
    #####################################shadow
    /etc/shadow
    ***Search for SSL related files***
    #####################################private
    /etc/ssl/private/server.key
A `#####...keyword` line is the current category; lines after it that start with
`/` are matched files.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from .base import Tool

# hitting these categories = credential/key leak, high severity
_HIGH = (
    "shadow", "passwd", "password", "private", "key", "pem", "psk",
    "ssh", "id_rsa", "secret", "credential", "htpasswd",
)


class FirmwalkerTool(Tool):
    id = "firmwalker"
    test = "FW-2"
    category = "FW"
    level = "L1"
    binary = "firmwalker"
    description = "Scan firmware filesystem for keys/passwords/hidden accounts"
    requires = ["firmware_extract_dir"]
    command_template = "firmwalker {firmware_extract_dir} {evidence}.txt"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        out_path = Path(f"{evidence}.txt")
        text = (
            out_path.read_text(encoding="utf-8", errors="replace")
            if out_path.exists()
            else raw
        )
        if not text:
            return []

        findings: List[dict] = []
        category = ""
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#####"):
                category = stripped.lstrip("#").strip()
                continue
            if stripped.startswith("***"):
                category = ""  # new section; wait for the next ##### category
                continue
            if stripped.startswith("/"):
                low = (category + " " + stripped).lower()
                high = any(k in low for k in _HIGH)
                findings.append(
                    {
                        "severity": "high" if high else "low",
                        "title": f"Firmware hit{f' [{category}]' if category else ''}",
                        "detail": stripped,
                    }
                )
        return findings
