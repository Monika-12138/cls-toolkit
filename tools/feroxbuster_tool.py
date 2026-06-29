"""feroxbuster —— 高性能目录/文件枚举，解析 --json (ndjson) 输出为发现路径 findings。

feroxbuster --json 把每条结果写成一行 JSON（newline-delimited JSON）：
  {"type":"response","url":"http://x/admin","status":200,"content_length":1234,...}
  {"type":"statistics",...}                # 汇总行，忽略
只取 type==response 的行。命中敏感关键词的路径标 low，其余 info（与 dirsearch 同口径）。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .base import Tool

# 与 dirsearch 一致的敏感路径关键词（管理面 / 备份 / 源码泄露 / 凭据）
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
    description = "高性能目录/文件枚举"
    requires = ["portal_url"]
    # -w 必填，否则 feroxbuster 直接报错退出。dirb 的 common.txt 是 Kali 自带字典，
    # 作为安全默认；想换更大的字典改这里（或装 seclists 后指向 raft-*-directories.txt）。
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
                    "title": f"发现路径 {url}",
                    "detail": detail,
                }
            )
        return findings
