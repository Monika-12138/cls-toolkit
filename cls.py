#!/usr/bin/env python3
"""CLS Toolkit -- command-line entry point.

  python3 cls.py list                 list all tool modules
  python3 cls.py check                check which tool binaries are installed
  python3 cls.py run --dut dut.yaml --tools nmap,testssl
  python3 cls.py run --dut dut.yaml --plan plan.yaml
  python3 cls.py report               summarize the latest run, export Markdown
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# make sure output works on any terminal (including Windows GBK consoles)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from core import report as report_mod
from core.dut import load_dut
from core.runner import run_pipeline
from tools.base import LEVELS
from tools.catalog import ALL_TOOLS, select


def cmd_list(_args) -> int:
    print(f"{'ID':<16}{'TEST':<14}{'CAT':<6}{'LV':<5}Description")
    print("-" * 78)
    for t in sorted(ALL_TOOLS, key=lambda x: (x.level, x.category, x.id)):
        print(f"{t.id:<16}{t.test:<14}{t.category:<6}{t.level:<5}{t.description}")
    print(f"\nTotal {len(ALL_TOOLS)} modules. Levels: " +
          " / ".join(f"{k} {v}" for k, v in LEVELS.items()))
    return 0


def cmd_check(_args) -> int:
    print(f"{'ID':<16}{'BINARY':<16}Status")
    print("-" * 48)
    missing = []
    for t in sorted(ALL_TOOLS, key=lambda x: x.id):
        if not t.auto:
            print(f"{t.id:<16}{'(manual)':<16}-")
            continue
        ok = t.available()
        print(f"{t.id:<16}{t.binary:<16}{'[+] installed' if ok else '[-] missing'}")
        if not ok:
            missing.append(t.binary)
    if missing:
        print(f"\nNot installed (apt/pip on Kali): {', '.join(sorted(set(missing)))}")
    return 0


def _resolve_tool_ids(args) -> list[str]:
    if args.tools:
        return [s.strip() for s in args.tools.split(",") if s.strip()]
    if args.plan:
        data = yaml.safe_load(Path(args.plan).read_text(encoding="utf-8")) or {}
        return list(data.get("pipeline", []))
    return []


def cmd_run(args) -> int:
    try:
        dut = load_dut(args.dut)
    except (FileNotFoundError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    tool_ids = _resolve_tool_ids(args)
    if not tool_ids:
        print("No tools specified. Use --tools nmap,testssl or --plan plan.yaml", file=sys.stderr)
        return 1

    tools, unknown = select(tool_ids)
    if unknown:
        print(f"Warning: unknown tool id (ignored): {', '.join(unknown)}\n"
              f"  `python3 cls.py list` to see valid ids", file=sys.stderr)
    if not tools:
        return 1

    print(f"DUT: {dut.get('toe_name', '?')} @ {dut.get('ip', '?')}")
    print(f"Pipeline ({len(tools)}): {' -> '.join(t.id for t in tools)}\n")

    report = run_pipeline(dut, tools)

    total = sum(len(r.get("findings", [])) for r in report["results"])
    print(f"\nDone. Structured results: {report['_path']}")
    print(f"Raw evidence dir: evidence/    total findings: {total}")
    return 0


def cmd_report(args) -> int:
    if args.results:
        path = Path(args.results)
        if not path.exists():
            print(f"Result file not found: {path}", file=sys.stderr)
            return 1
    else:
        path = report_mod.latest_results()
        if path is None:
            print("No results in results/ yet. Run `python3 cls.py run ...` first.",
                  file=sys.stderr)
            return 1

    report = report_mod.load(path)
    summary = report_mod.build_summary(report)
    print(report_mod.render_terminal(report, summary))

    md_path = report_mod.write_summary_md(report, str(path))
    print(f"\nMarkdown summary: {md_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cls", description="CLS test toolkit (Kali CLI)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all tool modules").set_defaults(func=cmd_list)
    sub.add_parser("check", help="Check which tool binaries are installed").set_defaults(func=cmd_check)

    run_p = sub.add_parser("run", help="Run a tool pipeline in order")
    run_p.add_argument("--dut", required=True, help="DUT config file (yaml)")
    run_p.add_argument("--tools", help="comma-separated tool ids, e.g. nmap,testssl")
    run_p.add_argument("--plan", help="pipeline yaml (pipeline: [...])")
    run_p.set_defaults(func=cmd_run)

    rep_p = sub.add_parser("report", help="Summarize results (by category + severity), export Markdown")
    rep_p.add_argument("--results", help="specific results json (default: newest in results/)")
    rep_p.set_defaults(func=cmd_report)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
