"""binwalk -- firmware unpacking; parse the signature scan table into findings.

binwalk's signature scan prints a table on stdout (present in every version):
  DECIMAL       HEXADECIMAL     DESCRIPTION
  --------------------------------------------------------------------------------
  0             0x0             uImage header, header size: 64 bytes ...
  112           0x70            LZMA compressed data ...
  1769472       0x1B0000        Squashfs filesystem, little endian ...
Each row is parsed as `<decimal> <0xHEX> <description>`. Filesystem / boot headers
= low (extractable, worth a look), private key / certificate / crypto = high, rest
= info. This gives a structured "what is the firmware made of" view; actual
credential leaks are left to firmwalker (FW-2).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

_ROW_RE = re.compile(r"^\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+\S)\s*$")
_FS_RE = re.compile(
    r"squashfs|jffs2|cramfs|romfs|ubifs|yaffs|ext[234]|filesystem|cpio|"
    r"uImage|u-boot|bootloader",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"private key|public key|certificate|encrypted|openssh|RSA|PGP|PEM|"
    r"password|crypt",
    re.IGNORECASE,
)


class BinwalkTool(Tool):
    id = "binwalk"
    test = "FW-1"
    category = "FW"
    level = "L1"
    binary = "binwalk"
    description = "Firmware unpacking, extract filesystem"
    requires = ["firmware_file"]
    command_template = "binwalk -Me {firmware_file}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        for line in raw.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue
            offset_hex, desc = m.group(2), m.group(3).strip()
            # the DESCRIPTION header row does not start with a digit, so _ROW_RE
            # already excludes it
            if _SECRET_RE.search(desc):
                sev = "high"
            elif _FS_RE.search(desc):
                sev = "low"
            else:
                sev = "info"
            findings.append(
                {
                    "severity": sev,
                    "title": f"Firmware signature @ {offset_hex}",
                    "detail": desc,
                }
            )
        return findings
