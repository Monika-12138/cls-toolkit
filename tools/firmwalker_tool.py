"""firmwalker —— 扫描固件文件系统中的密钥/密码/隐藏账户，解析输出文本为命中 findings。

firmwalker 把结果写进输出文件，结构形如：
    ***Search for password files***
    #####################################passwd
    /etc/passwd
    #####################################shadow
    /etc/shadow
    ***Search for SSL related files***
    #####################################private
    /etc/ssl/private/server.key
`#####...keyword` 行是当前类别，其后以 `/` 开头的行是命中文件。
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from .base import Tool

# 命中这些类别 = 凭据/密钥泄露，高危
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
    description = "扫描固件文件系统中的密钥/密码/隐藏账户"
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
                category = ""  # 进入新 section，等下一个 ##### 给出具体类别
                continue
            if stripped.startswith("/"):
                low = (category + " " + stripped).lower()
                high = any(k in low for k in _HIGH)
                findings.append(
                    {
                        "severity": "high" if high else "low",
                        "title": f"固件命中{f' [{category}]' if category else ''}",
                        "detail": stripped,
                    }
                )
        return findings
