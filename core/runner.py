"""执行引擎 —— 按顺序跑一条工具流水线，落证据 + 结构化结果。"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List

from tools.base import Tool

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = ROOT / "evidence"
RESULTS_DIR = ROOT / "results"


def run_pipeline(dut: dict, tools: List[Tool]) -> dict:
    EVIDENCE_DIR.mkdir(exist_ok=True)
    RESULTS_DIR.mkdir(exist_ok=True)

    results = []
    for idx, tool in enumerate(tools, 1):
        label = f"[{idx}/{len(tools)}] {tool.id} ({tool.test})"

        if not tool.auto:
            print(f"{label}  →  人工/硬件，跳过执行（已记为占位）")
            results.append(tool.run(dut, EVIDENCE_DIR))
            continue

        if not tool.available():
            print(f"{label}  →  跳过：未安装 {tool.binary}")
            results.append({
                "tool": tool.id, "test": tool.test, "level": tool.level,
                "status": "skipped-no-binary", "findings": [],
                "note": f"本机未安装 {tool.binary}",
            })
            continue

        missing = tool.missing_fields(dut)
        if missing:
            print(f"{label}  →  跳过：DUT 缺字段 {missing}")
            results.append({
                "tool": tool.id, "test": tool.test, "level": tool.level,
                "status": "skipped-missing-fields", "findings": [],
                "note": f"DUT 缺字段: {', '.join(missing)}",
            })
            continue

        print(f"{label}  →  执行中…")
        res = tool.run(dut, EVIDENCE_DIR)
        n = len(res.get("findings", []))
        print(f"{label}  →  {res['status']}（{n} findings）")
        results.append(res)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "dut": dut,
        "results": results,
    }
    out_path = RESULTS_DIR / f"results_{stamp}.json"
    out_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    report["_path"] = str(out_path)
    return report
