"""binwalk —— 固件解包，解析签名扫描表为固件组成 findings。

binwalk 的签名扫描在 stdout 打印一张表（任何版本都有）：
  DECIMAL       HEXADECIMAL     DESCRIPTION
  --------------------------------------------------------------------------------
  0             0x0             uImage header, header size: 64 bytes ...
  112           0x70            LZMA compressed data ...
  1769472       0x1B0000        Squashfs filesystem, little endian ...
逐行抓 `<十进制> <0x十六进制> <描述>`。文件系统/引导头=low（可提取，值得看），
私钥/证书/加密相关=high，其余 info。这给出固件「由什么组成」的结构化视图，
具体凭据泄露交给 firmwalker（FW-2）。
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
    description = "固件解包，提取文件系统"
    requires = ["firmware_file"]
    command_template = "binwalk -Me {firmware_file}"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        for line in raw.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue
            offset_hex, desc = m.group(2), m.group(3).strip()
            # 跳过表头被误匹配的可能性（DESCRIPTION 行不是数字开头，正则已排除）
            if _SECRET_RE.search(desc):
                sev = "high"
            elif _FS_RE.search(desc):
                sev = "low"
            else:
                sev = "info"
            findings.append(
                {
                    "severity": sev,
                    "title": f"固件签名 @ {offset_hex}",
                    "detail": desc,
                }
            )
        return findings
