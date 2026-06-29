"""Load / validate DUT pre-flight info (dut.yaml)."""
from __future__ import annotations

from pathlib import Path

import yaml


def load_dut(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"DUT config not found: {path}\n  Run `cp dut.example.yaml dut.yaml` then fill it in."
        )
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a key: value mapping.")
    # stringify everything; safer for command injection
    return {k: ("" if v is None else str(v)) for k, v in data.items()}
