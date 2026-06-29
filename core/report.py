"""结果汇总 —— 把一次 run 的 results_*.json 聚合成可读报告。

- 按严重度统计 findings
- 按 CLS 测试类别（PS/FW/CO/CP/...）分组列出每个工具与其 findings
- 汇总「需人工跟进 / 未完成」清单（跳过 / 人工占位 / 执行失败）
- 输出：终端摘要 + 一份 Markdown（results/summary_<stamp>.md）

这份 Markdown 是 Part 1（跑工具拿数据）到 Part 2（AI 套 CLS 模板写报告）的交接物：
结构已按 CLS 类别组织，AI 只需读它 + 模板就能起草 provision 结论。
"""
from __future__ import annotations

import glob
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "results"

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {
    "critical": "严重", "high": "高危", "medium": "中危",
    "low": "低危", "info": "信息",
}
SEV_ICON = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

CAT_NAMES = {
    "PS": "Ports and Services 端口与服务",
    "FW": "Firmware 固件",
    "FWU": "Firmware Updates 固件更新",
    "CO": "Communications 通信",
    "CP": "Configuration Portal 配置门户",
    "MA": "Mobile Application 手机 App",
    "AU": "Authentication 认证",
    "AWR": "Wireless Router 无线路由器专项",
    "OA": "Other Attacks 其他攻击",
    "HW": "Hardware 硬件",
}
CAT_ORDER = list(CAT_NAMES.keys())

# 状态归类
_SKIPPED = {"skipped-no-binary", "skipped-missing-fields"}
_FAILED = {"error", "timeout", "missing-binary"}


def latest_results(results_dir: Path = RESULTS_DIR) -> Optional[Path]:
    """返回 results/ 下时间戳最新的 results_*.json（文件名含时间戳，按名排序即可）。"""
    files = sorted(glob.glob(str(results_dir / "results_*.json")))
    return Path(files[-1]) if files else None


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _category(result: dict) -> str:
    cat = (result.get("category") or "").strip()
    if cat:
        return cat
    test = result.get("test", "")
    return (test.split("-")[0].split("/")[0] or "?").strip() or "?"


def _sev(finding: dict) -> str:
    sev = str(finding.get("severity", "info")).lower()
    return sev if sev in SEV_LABEL else "info"


def build_summary(report: dict) -> dict:
    results: List[dict] = report.get("results", [])

    sev_counts = {s: 0 for s in SEV_ORDER}
    status_counts = {"ran": 0, "skipped": 0, "manual": 0, "failed": 0}
    follow_up: List[dict] = []

    for r in results:
        status = r.get("status", "")
        if status == "manual":
            status_counts["manual"] += 1
            follow_up.append(r)
        elif status in _SKIPPED:
            status_counts["skipped"] += 1
            follow_up.append(r)
        elif status in _FAILED:
            status_counts["failed"] += 1
            follow_up.append(r)
        else:  # done
            status_counts["ran"] += 1

        for f in r.get("findings", []):
            sev_counts[_sev(f)] += 1

    # 按类别分组（保留原顺序）
    by_cat: dict[str, List[dict]] = {}
    for r in results:
        by_cat.setdefault(_category(r), []).append(r)

    return {
        "sev_counts": sev_counts,
        "status_counts": status_counts,
        "total_findings": sum(sev_counts.values()),
        "by_cat": by_cat,
        "follow_up": follow_up,
        "n_tools": len(results),
    }


def _ordered_cats(by_cat: dict) -> List[str]:
    known = [c for c in CAT_ORDER if c in by_cat]
    extra = sorted(c for c in by_cat if c not in CAT_ORDER)
    return known + extra


def _status_zh(status: str) -> str:
    return {
        "done": "已执行", "manual": "人工待办", "error": "执行失败",
        "timeout": "超时", "missing-binary": "缺二进制",
        "skipped-no-binary": "跳过(未装)", "skipped-missing-fields": "跳过(缺字段)",
    }.get(status, status or "?")


def render_markdown(report: dict, summary: dict, source: str) -> str:
    dut = report.get("dut", {})
    name = dut.get("toe_name", "?")
    sc = summary["status_counts"]
    lines: List[str] = []

    lines.append(f"# CLS 测试结果汇总 — {name}")
    lines.append("")
    lines.append("> 由 `cls.py report` 自动生成；作为人工复核 + Part 2（AI 套 CLS 模板写报告）的输入。")
    lines.append("> findings 仅是工具输出的机器初判，**PASS/FAIL/NA 最终结论需评测员复核**。")
    lines.append("")
    lines.append(f"- **DUT**: {name}"
                 + (f"（{dut.get('model')}）" if dut.get("model") else "")
                 + f" @ {dut.get('ip', '?')}")
    lines.append(f"- **生成时间**: {report.get('generated_at', '?')}")
    lines.append(f"- **结果文件**: `{source}`")
    lines.append(f"- **模块**: 共 {summary['n_tools']}"
                 f"（已执行 {sc['ran']} · 跳过 {sc['skipped']} · 人工 {sc['manual']} · 失败 {sc['failed']}）")
    lines.append("")

    # 严重度统计
    lines.append("## 严重度统计")
    lines.append("")
    lines.append("| 严重度 | 数量 |")
    lines.append("|---|---:|")
    for s in SEV_ORDER:
        lines.append(f"| {SEV_ICON[s]} {SEV_LABEL[s]} | {summary['sev_counts'][s]} |")
    lines.append(f"| **合计** | **{summary['total_findings']}** |")
    lines.append("")

    # 按类别
    lines.append("## 按 CLS 测试类别")
    lines.append("")
    for cat in _ordered_cats(summary["by_cat"]):
        title = CAT_NAMES.get(cat, cat)
        lines.append(f"### {cat} — {title}")
        lines.append("")
        lines.append("| 工具 | Test | 状态 | findings |")
        lines.append("|---|---|---|---:|")
        for r in summary["by_cat"][cat]:
            lines.append(
                f"| {r.get('tool', '?')} | {r.get('test', '?')} "
                f"| {_status_zh(r.get('status', ''))} | {len(r.get('findings', []))} |"
            )
        lines.append("")
        # 详细 findings（每个工具，按严重度排序）
        for r in summary["by_cat"][cat]:
            fs = r.get("findings", [])
            if not fs:
                continue
            lines.append(f"**{r.get('tool', '?')}** ({r.get('test', '?')})")
            lines.append("")
            for f in sorted(fs, key=lambda x: SEV_ORDER.index(_sev(x))):
                sev = _sev(f)
                detail = f.get("detail", "")
                lines.append(
                    f"- {SEV_ICON[sev]} `{SEV_LABEL[sev]}` "
                    f"{f.get('title', '')}" + (f" — {detail}" if detail else "")
                )
            lines.append("")

    # 需人工跟进
    lines.append("## 需人工跟进 / 未完成")
    lines.append("")
    if not summary["follow_up"]:
        lines.append("（无）")
    else:
        for r in summary["follow_up"]:
            note = r.get("note") or r.get("description") or _status_zh(r.get("status", ""))
            lines.append(
                f"- [ ] **{r.get('tool', '?')}** ({r.get('test', '?')}) "
                f"· {_status_zh(r.get('status', ''))} · {note}"
            )
    lines.append("")
    return "\n".join(lines)


def render_terminal(report: dict, summary: dict) -> str:
    dut = report.get("dut", {})
    sc = summary["status_counts"]
    out: List[str] = []
    out.append(f"DUT: {dut.get('toe_name', '?')} @ {dut.get('ip', '?')}")
    out.append(f"模块: 共 {summary['n_tools']}（执行 {sc['ran']} · 跳过 {sc['skipped']} "
               f"· 人工 {sc['manual']} · 失败 {sc['failed']}）")
    tally = "  ".join(
        f"{SEV_ICON[s]}{SEV_LABEL[s]} {summary['sev_counts'][s]}" for s in SEV_ORDER
    )
    out.append(f"findings: {summary['total_findings']}  [{tally}]")
    out.append("")
    out.append("按类别:")
    for cat in _ordered_cats(summary["by_cat"]):
        rows = summary["by_cat"][cat]
        nfind = sum(len(r.get("findings", [])) for r in rows)
        tools = ", ".join(r.get("tool", "?") for r in rows)
        out.append(f"  {cat:<4} {CAT_NAMES.get(cat, cat):<28} {nfind:>3} findings  ({tools})")
    if summary["follow_up"]:
        out.append("")
        out.append(f"需人工跟进: {len(summary['follow_up'])} 项（详见 Markdown）")
    return "\n".join(out)


def write_summary_md(report: dict, source: str, results_dir: Path = RESULTS_DIR) -> Path:
    """生成汇总并写 Markdown，返回写入路径。"""
    summary = build_summary(report)
    md = render_markdown(report, summary, source)
    results_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = results_dir / f"summary_{stamp}.md"
    out_path.write_text(md, encoding="utf-8")
    return out_path
