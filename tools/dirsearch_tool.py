"""dirsearch —— 配置门户隐藏路径/管理接口爆破，解析 JSON 报告为发现路径 findings。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .base import Tool

# 命中这些关键词的路径更值得关注（管理面 / 备份 / 源码泄露 / 凭据）
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
    description = "配置门户隐藏路径/管理接口爆破"
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
                    "title": f"发现路径 {url}",
                    "detail": detail,
                }
            )
        return findings


def _iter_results(data) -> List[dict]:
    """兼容多种 dirsearch JSON 形态：
      - {"results": [ {...}, ... ]}
      - {"<target-url>": [ {...}, ... ]}  (旧版按 target 分组)
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
