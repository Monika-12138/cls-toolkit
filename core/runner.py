"""Execution engine -- run one tool pipeline in order, save evidence + structured results."""
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
            print(f"{label}  ->  manual/hardware, skipped (recorded as placeholder)")
            results.append(tool.run(dut, EVIDENCE_DIR))
            continue

        if not tool.available():
            print(f"{label}  ->  skipped: {tool.binary} not installed")
            results.append({
                "tool": tool.id, "test": tool.test, "category": tool.category,
                "level": tool.level, "status": "skipped-no-binary", "findings": [],
                "note": f"{tool.binary} not installed on this host",
            })
            continue

        missing = tool.missing_fields(dut)
        if missing:
            print(f"{label}  ->  skipped: DUT missing fields {missing}")
            results.append({
                "tool": tool.id, "test": tool.test, "category": tool.category,
                "level": tool.level, "status": "skipped-missing-fields", "findings": [],
                "note": f"DUT missing fields: {', '.join(missing)}",
            })
            continue

        print(f"{label}  ->  running...")
        res = tool.run(dut, EVIDENCE_DIR)
        n = len(res.get("findings", []))
        print(f"{label}  ->  {res['status']} ({n} findings)")
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
