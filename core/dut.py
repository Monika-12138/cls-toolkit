"""读取 / 校验 DUT 前置信息（dut.yaml）。"""
from __future__ import annotations

from pathlib import Path

import yaml


def load_dut(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"找不到 DUT 配置: {path}\n  先 `cp dut.example.yaml dut.yaml` 再填写。"
        )
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} 顶层应为 key: value 映射。")
    # 全部转成字符串，命令注入时更安全
    return {k: ("" if v is None else str(v)) for k, v in data.items()}
