#!/usr/bin/env python3
"""CLS Toolkit —— 命令行入口。

  python3 cls.py list                 列出所有工具模块
  python3 cls.py check                检查本机装了哪些工具二进制
  python3 cls.py run --dut dut.yaml --tools nmap,testssl
  python3 cls.py run --dut dut.yaml --plan plan.yaml
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# 确保中文 / ✓✗ 在任何终端（含 Windows GBK 控制台）都能输出，不崩
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from core.dut import load_dut
from core.runner import run_pipeline
from tools.base import LEVELS
from tools.catalog import ALL_TOOLS, select


def cmd_list(_args) -> int:
    print(f"{'ID':<16}{'TEST':<14}{'CAT':<6}{'LV':<5}说明")
    print("-" * 78)
    for t in sorted(ALL_TOOLS, key=lambda x: (x.level, x.category, x.id)):
        print(f"{t.id:<16}{t.test:<14}{t.category:<6}{t.level:<5}{t.description}")
    print(f"\n共 {len(ALL_TOOLS)} 个模块。等级：" +
          " / ".join(f"{k} {v}" for k, v in LEVELS.items()))
    return 0


def cmd_check(_args) -> int:
    print(f"{'ID':<16}{'BINARY':<16}状态")
    print("-" * 48)
    missing = []
    for t in sorted(ALL_TOOLS, key=lambda x: x.id):
        if not t.auto:
            print(f"{t.id:<16}{'(人工)':<16}—")
            continue
        ok = t.available()
        print(f"{t.id:<16}{t.binary:<16}{'✓ 已安装' if ok else '✗ 未安装'}")
        if not ok:
            missing.append(t.binary)
    if missing:
        print(f"\n未安装（在 Kali 上 apt/pip 装）：{', '.join(sorted(set(missing)))}")
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
        print("没有指定工具。用 --tools nmap,testssl 或 --plan plan.yaml", file=sys.stderr)
        return 1

    tools, unknown = select(tool_ids)
    if unknown:
        print(f"⚠ 未知工具 id（已忽略）：{', '.join(unknown)}\n  `python3 cls.py list` 看可用 id", file=sys.stderr)
    if not tools:
        return 1

    print(f"DUT: {dut.get('toe_name', '?')} @ {dut.get('ip', '?')}")
    print(f"流水线（{len(tools)}）：{' → '.join(t.id for t in tools)}\n")

    report = run_pipeline(dut, tools)

    total = sum(len(r.get("findings", [])) for r in report["results"])
    print(f"\n完成。结构化结果：{report['_path']}")
    print(f"原始证据目录：evidence/    findings 总数：{total}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cls", description="CLS 测试工具合集（Kali CLI）")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="列出所有工具模块").set_defaults(func=cmd_list)
    sub.add_parser("check", help="检查本机工具二进制").set_defaults(func=cmd_check)

    run_p = sub.add_parser("run", help="按顺序执行工具流水线")
    run_p.add_argument("--dut", required=True, help="DUT 配置文件（yaml）")
    run_p.add_argument("--tools", help="逗号分隔的工具 id，如 nmap,testssl")
    run_p.add_argument("--plan", help="流水线 yaml（pipeline: [...]）")
    run_p.set_defaults(func=cmd_run)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
