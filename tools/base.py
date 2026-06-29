"""Tool base classes for the CLS toolkit.

每个测试工具 = 一个 Tool 子类。统一接口：
  - command_template / build_command : 把 DUT 信息注入命令
  - run                              : 执行 + 抓输出 + 存证据
  - parse                            : 原始输出 -> 结构化 findings（默认不解析，子类重写）
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List

LEVELS = {
    "L1": "全自动",
    "L2": "半自动(需证据)",
    "L3": "人工/硬件",
}


class _SafeDict(dict):
    """str.format_map 用：缺失的占位符渲染成空字符串而不是报错。"""

    def __missing__(self, key):  # noqa: D401
        return ""


class Tool:
    id: str = ""                    # 唯一 id，如 "nmap"
    test: str = ""                  # CLS test code，如 "PS-1"
    category: str = ""              # PS / FW / CO / CP / MA / AU / AWR / HW
    level: str = "L1"               # L1 全自动 / L2 半自动 / L3 人工
    binary: str = ""                # 需要的二进制（PATH 检测），空=不检测
    description: str = ""
    requires: List[str] = []        # 必填的 DUT 字段，缺则跳过执行
    command_template: str = ""      # 占位符 {field} + {evidence}
    timeout: int = 600              # 秒
    auto: bool = True               # False = 人工/硬件，不代跑

    # ---- 能力检测 ----
    def available(self) -> bool:
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def missing_fields(self, dut: dict) -> List[str]:
        return [f for f in self.requires if not str(dut.get(f, "")).strip()]

    # ---- 命令构建 ----
    def build_command(self, dut: dict, evidence: Path) -> List[str]:
        ctx = _SafeDict(dut)
        ctx["evidence"] = str(evidence)
        rendered = self.command_template.format_map(ctx)
        return shlex.split(rendered)

    # ---- 执行 ----
    def run(self, dut: dict, evidence_dir: Path) -> dict:
        safe = f"{self.id}_{self.test}".replace("/", "-")
        evidence = evidence_dir / safe
        argv = self.build_command(dut, evidence)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout
            )
            raw = proc.stdout
            if proc.stderr:
                raw += "\n[stderr]\n" + proc.stderr
            exit_code = proc.returncode
            status = "done" if exit_code == 0 else "error"
        except subprocess.TimeoutExpired:
            raw, exit_code, status = f"[超时 {self.timeout}s]", -1, "timeout"
        except FileNotFoundError:
            raw, exit_code, status = f"[未找到二进制: {self.binary}]", -2, "missing-binary"

        log_path = evidence_dir / f"{safe}.log"
        log_path.write_text(raw, encoding="utf-8", errors="replace")

        findings = []
        if status == "done":
            try:
                findings = self.parse(raw, evidence)
            except Exception as exc:  # noqa: BLE001  解析失败不应中断流水线
                findings = [{"severity": "info", "title": "parse 失败", "detail": str(exc)}]

        return {
            "tool": self.id,
            "test": self.test,
            "category": self.category,
            "level": self.level,
            "command": " ".join(argv),
            "exit_code": exit_code,
            "status": status,
            "evidence_log": str(log_path),
            "findings": findings,
        }

    def parse(self, raw: str, evidence: Path) -> List[dict]:
        """默认不做结构化解析（原始输出已存进 .log）。子类重写以提取 findings。"""
        return []


class ManualTool(Tool):
    """L2/L3：人工或硬件步骤，平台只占位、不代跑。"""

    auto = False

    def run(self, dut: dict, evidence_dir: Path) -> dict:
        return {
            "tool": self.id,
            "test": self.test,
            "category": self.category,
            "level": self.level,
            "command": self.command_template or "（人工步骤）",
            "exit_code": None,
            "status": "manual",
            "evidence_log": None,
            "findings": [],
            "note": self.description or "人工/硬件步骤，需评测员手动执行并上传证据。",
        }
