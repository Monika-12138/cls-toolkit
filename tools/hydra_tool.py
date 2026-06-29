"""hydra -- login brute-force; parse cracked credentials from stdout into findings.

On success hydra prints lines like:
  [80][http-get] host: 192.168.1.1   login: admin   password: admin
Each one is a matched credential pair. For CLS, "weak/default credentials can be
brute-forced" is high severity (AU-1 brute-force resistance / default password),
so each hit is recorded as high.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

# login / password values may be empty (password: ""); split fields loosely
_CRED_RE = re.compile(
    r"\[(\d+)\]\[([^\]]+)\]\s+host:\s*(\S+)\s+"
    r"login:\s*(\S*)\s+password:\s*(\S*)",
    re.IGNORECASE,
)


class HydraTool(Tool):
    id = "hydra"
    test = "AU-1"
    category = "AU"
    level = "L1"
    binary = "hydra"
    description = "Login brute-force resistance check"
    requires = ["ip", "users_file", "pass_file"]
    command_template = "hydra -L {users_file} -P {pass_file} {ip} http-get /"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        seen: set[tuple] = set()
        for m in _CRED_RE.finditer(raw):
            port, service, host = m.group(1), m.group(2), m.group(3)
            login, password = m.group(4) or "(empty)", m.group(5) or "(empty)"
            key = (host, port, login, password)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "severity": "high",
                    "title": f"Cracked credential: {login} / {password}",
                    "detail": f"{host}:{port} ({service})",
                }
            )
        return findings
