"""hydra —— 登录接口暴力破解，解析 stdout 中破解成功的凭据为 findings。

hydra 破解成功会打印形如：
  [80][http-get] host: 192.168.1.1   login: admin   password: admin
每条 = 一组命中的账号口令。对 CLS 而言「能被爆破出弱口令/默认口令」是高危
（AU-1 抗暴力破解 / 默认密码相关），所以每条命中记为 high。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .base import Tool

# login / password 值可能为空（password: ""），用非贪婪到行尾的字段切分
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
    description = "登录接口抗暴力破解验证"
    requires = ["ip", "users_file", "pass_file"]
    command_template = "hydra -L {users_file} -P {pass_file} {ip} http-get /"

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        findings: List[dict] = []
        seen: set[tuple] = set()
        for m in _CRED_RE.finditer(raw):
            port, service, host = m.group(1), m.group(2), m.group(3)
            login, password = m.group(4) or "(空)", m.group(5) or "(空)"
            key = (host, port, login, password)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "severity": "high",
                    "title": f"爆破命中凭据: {login} / {password}",
                    "detail": f"{host}:{port} ({service})",
                }
            )
        return findings
